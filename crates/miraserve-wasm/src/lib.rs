#![forbid(unsafe_code)]
//! Sandboxed WebAssembly (`wasmtime` + `wasi:http`) plugin runtime for MiraServe
//! enforcing Threat Model T7:
//! - Deterministic CPU instruction fuel limits (`consume_fuel` + `fuel_async_yield_interval` +
//!   proportional host-call fuel accounting)
//! - Preemptive OS epoch-interruption ticker enforcing wall-clock `timeout` even on tight loops
//! - Strict linear memory & WASI host-resource ceilings (`StoreLimits`, `ResourceTable` cap,
//!   field-size & outgoing-body chunk caps, concurrent streaming response collection)
//! - Framing, hop-by-hop, `Host`, and `Alt-Svc` header sanitization on all plugin responses
//! - Safe scratch-page / pull-import marshaling (never overwriting guest linear memory offset 0)
//! - Zero ambient filesystem, environment, CLI argument, or outbound network capabilities

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, HeaderName, HeaderValue};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full, Limited};
use miraserve_config::WasmPluginConfig;
use thiserror::Error;
use tracing::warn;
use wasmtime::component::{Component, Linker as ComponentLinker, ResourceTable};
use wasmtime::{
    Caller, Config as WasmConfig, Engine, Linker as CoreLinker, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap,
};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::bindings::ProxyPre;
use wasmtime_wasi_http::p2::bindings::http::types::Scheme as WasiScheme;
use wasmtime_wasi_http::{
    Error as WasiHttpError, RequestOptions, WasiBody, WasiHttpCtx, WasiHttpCtxView, WasiHttpHooks,
    WasiHttpView,
};

/// Maximum response body accepted back from a sandboxed WASM plugin (4 MiB).
const MAX_PLUGIN_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum response headers a core WASM plugin may emit.
const MAX_PLUGIN_HEADERS: usize = 64;
/// Maximum `.wasm` / `.wat` plugin file size read from disk (32 MiB).
const MAX_WASM_MODULE_BYTES: u64 = 32 * 1024 * 1024;
/// Cooperative fuel yield interval preventing Tokio worker starvation.
const FUEL_ASYNC_YIELD_INTERVAL: u64 = 10_000;
/// Preemptive epoch ticker granularity in milliseconds.
const EPOCH_TICK_MS: u64 = 10;
/// Maximum live WASI resource handles per request (defeats `ResourceTable` host OOM).
const MAX_WASI_RESOURCE_TABLE_CAPACITY: usize = 64;
/// Maximum aggregate WASI HTTP field map size (16 KiB).
const MAX_WASI_HTTP_FIELD_BYTES: usize = 16 * 1024;
/// Outgoing WASI HTTP body chunk size (64 KiB) & in-flight buffer depth (1 chunk).
const WASI_OUTGOING_BODY_CHUNK_BYTES: usize = 64 * 1024;
const WASI_OUTGOING_BODY_BUFFER_CHUNKS: usize = 1;
/// WASM linear memory page size in bytes (64 KiB).
const WASM_PAGE_BYTES: usize = 65_536;

/// Errors produced when compiling or executing a sandboxed WASM plugin.
#[derive(Debug, Error)]
pub enum WasmError {
    /// Failed to read the `.wasm` / `.wat` plugin file from disk.
    #[error("failed to read WASM plugin '{path}': {source}")]
    Io {
        /// Path to the plugin module.
        path: PathBuf,
        /// Underlying OS I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Wasmtime engine or module/component compilation error.
    #[error("WASM compilation/setup error: {0}")]
    Compile(String),
    /// Plugin exhausted its per-request deterministic CPU fuel budget (infinite loop defense).
    #[error("WASM plugin exceeded CPU fuel budget ({budget} instructions)")]
    FuelExhausted {
        /// Configured per-request fuel cap.
        budget: u64,
    },
    /// Plugin exceeded its linear memory ceiling (`max_memory`).
    #[error("WASM plugin exceeded linear memory ceiling ({max_bytes} bytes)")]
    MemoryLimitExceeded {
        /// Configured per-request memory cap.
        max_bytes: usize,
    },
    /// Plugin exceeded its wall-clock execution timeout.
    #[error("WASM plugin exceeded execution timeout ({timeout_ms}ms)")]
    Timeout {
        /// Configured wall-clock timeout in milliseconds.
        timeout_ms: u128,
    },
    /// Plugin trapped or failed during execution.
    #[error("WASM plugin runtime trap: {0}")]
    Trap(String),
}

impl WasmError {
    /// Maps a [`WasmError`] to an HTTP status code and stable telemetry outcome label.
    #[must_use]
    pub const fn http_status_and_label(&self) -> (StatusCode, &'static str) {
        match self {
            Self::FuelExhausted { .. } => (StatusCode::GATEWAY_TIMEOUT, "fuel_exhausted"),
            Self::Timeout { .. } => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            Self::MemoryLimitExceeded { .. } => (StatusCode::SERVICE_UNAVAILABLE, "memory_limit"),
            Self::Io { .. } | Self::Compile(_) | Self::Trap(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "trap")
            }
        }
    }

    /// Returns `true` when the failure was a sandbox resource/DoS enforcement block
    /// (fuel exhaustion, memory limit, or timeout) rather than a generic plugin runtime bug.
    #[must_use]
    pub const fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::FuelExhausted { .. } | Self::MemoryLimitExceeded { .. } | Self::Timeout { .. }
        )
    }

    /// Returns a generic client-safe response message without leaking raw Wasmtime internals (`WASM-4`).
    #[must_use]
    pub const fn client_safe_message(&self) -> &'static str {
        match self {
            Self::FuelExhausted { .. } | Self::Timeout { .. } => "504 Gateway Timeout\n",
            Self::MemoryLimitExceeded { .. } => "503 Service Unavailable\n",
            Self::Io { .. } | Self::Compile(_) | Self::Trap(_) => "500 Internal Server Error\n",
        }
    }
}

/// Successful execution result returned by [`WasmPluginRuntime::execute`].
#[derive(Debug)]
pub struct WasmExecutionResult {
    /// HTTP response produced by the sandboxed plugin.
    pub response: Response<Bytes>,
    /// Exact deterministic Wasmtime CPU fuel consumed by this request.
    pub fuel_consumed: u64,
}

/// Compiled WebAssembly plugin artifact (WASI `wasi:http/proxy` component or core Wasm module).
enum CompiledPlugin {
    WasiHttpComponent(ProxyPre<WasiHostState>),
    CoreModule(Module),
}

/// Thread-safe, pre-compiled sandboxed WebAssembly plugin runtime for a single route.
pub struct WasmPluginRuntime {
    engine: Engine,
    config: WasmPluginConfig,
    compiled: CompiledPlugin,
    stop_ticker: Arc<AtomicBool>,
}

impl Drop for WasmPluginRuntime {
    fn drop(&mut self) {
        self.stop_ticker.store(true, Ordering::Release);
    }
}

impl fmt::Debug for WasmPluginRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.compiled {
            CompiledPlugin::WasiHttpComponent(_) => "wasi:http/proxy-component",
            CompiledPlugin::CoreModule(_) => "core-wasm-module",
        };
        f.debug_struct("WasmPluginRuntime")
            .field("kind", &kind)
            .field("module_path", &self.config.module_path)
            .field("max_memory_bytes", &self.config.max_memory.as_bytes())
            .field("max_fuel", &self.config.max_fuel)
            .field("timeout", &self.config.timeout)
            .finish_non_exhaustive()
    }
}

impl WasmPluginRuntime {
    /// Loads and compiles a `.wasm` / `.wat` plugin from `config.module_path` with a strict
    /// regular-file check and 32 MiB size ceiling (defeating FIFO/OOM file-read abuse).
    ///
    /// # Errors
    /// Returns [`WasmError`] if the file is non-regular, exceeds 32 MiB, cannot be read,
    /// or fails compilation/linking.
    pub fn from_config(config: WasmPluginConfig) -> Result<Self, WasmError> {
        let configured = PathBuf::from(&config.module_path);
        let path = if configured.is_absolute() {
            configured
        } else {
            std::env::current_dir()
                .map_err(|source| WasmError::Io {
                    path: configured.clone(),
                    source,
                })?
                .join(&configured)
        };
        // Codex Round-5 P1 #3: the tenant module is read with the SAME no-follow rule as
        // absolute custom error pages (no symlink/reparse point in any component, non-blocking
        // regular-file leaf, bounded size) — exactly the rule the sandbox uses to decide whether
        // the module is trusted. A refused module isolates only its route to 503.
        let raw = miraserve_static::read_no_symlink_file(&path, MAX_WASM_MODULE_BYTES).map_err(
            |reason| WasmError::Io {
                path: path.clone(),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, reason),
            },
        )?;
        Self::from_bytes(config, &raw)
    }

    /// Compiles a `.wasm` binary or `.wat` text source directly from memory.
    ///
    /// # Errors
    /// Returns [`WasmError::Compile`] if the artifact is invalid or fails linking.
    pub fn from_bytes(config: WasmPluginConfig, bytes: &[u8]) -> Result<Self, WasmError> {
        let mut wasm_cfg = WasmConfig::new();
        wasm_cfg.consume_fuel(true);
        wasm_cfg.epoch_interruption(true);
        wasm_cfg.wasm_component_model(true);

        let engine = Engine::new(&wasm_cfg).map_err(|err| {
            WasmError::Compile(format!("failed to create Wasmtime engine: {err}"))
        })?;

        let compiled = if is_component_source(bytes) {
            let component = Component::new(&engine, bytes)
                .map_err(|err| WasmError::Compile(format!("invalid WASM component: {err}")))?;
            let mut linker: ComponentLinker<WasiHostState> = ComponentLinker::new(&engine);
            wasmtime_wasi::p2::add_to_linker_async(&mut linker)
                .map_err(|err| WasmError::Compile(format!("failed to link WASI p2: {err}")))?;
            wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)
                .map_err(|err| WasmError::Compile(format!("failed to link wasi:http: {err}")))?;
            let inst_pre = linker.instantiate_pre(&component).map_err(|err| {
                WasmError::Compile(format!("component pre-instantiation failed: {err}"))
            })?;
            let proxy_pre = ProxyPre::new(inst_pre).map_err(|err| {
                WasmError::Compile(format!(
                    "component does not export wasi:http/proxy world: {err}"
                ))
            })?;
            CompiledPlugin::WasiHttpComponent(proxy_pre)
        } else {
            let module = Module::new(&engine, bytes)
                .map_err(|err| WasmError::Compile(format!("invalid core WASM module: {err}")))?;
            CompiledPlugin::CoreModule(module)
        };

        // Dedicated OS ticker thread increments Wasmtime's epoch every 10ms so wall-clock
        // timeouts preempt tight guest loops even under full CPU saturation (`R2-WASM-1`).
        let stop_ticker = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop_ticker);
        let engine_c = engine.clone();
        std::thread::Builder::new()
            .name("miraserve-wasm-epoch".to_owned())
            .spawn(move || {
                while !stop_c.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                    engine_c.increment_epoch();
                }
            })
            .map_err(|err| {
                WasmError::Compile(format!(
                    "failed to spawn WASM epoch watchdog thread (required for wall-clock preemption): {err}"
                ))
            })?;

        Ok(Self {
            engine,
            config,
            compiled,
            stop_ticker,
        })
    }

    /// Returns the plugin's sandbox policy configuration.
    #[must_use]
    pub const fn config(&self) -> &WasmPluginConfig {
        &self.config
    }

    /// Executes the sandboxed plugin on an incoming HTTP request under strict CPU fuel,
    /// epoch preemption, linear memory, and wall-clock timeout isolation.
    ///
    /// # Errors
    /// Returns [`WasmError`] on fuel exhaustion, memory limit violation, timeout, or trap.
    pub async fn execute(
        &self,
        req: Request<Bytes>,
        is_https: bool,
    ) -> Result<WasmExecutionResult, WasmError> {
        let timeout = self.config.timeout;
        let fut = async {
            match &self.compiled {
                CompiledPlugin::WasiHttpComponent(pre) => {
                    self.execute_wasi_component(pre, req, is_https).await
                }
                CompiledPlugin::CoreModule(module) => self.execute_core_module(module, &req).await,
            }
        };

        tokio::time::timeout(timeout, fut)
            .await
            .unwrap_or_else(|_| {
                warn!(
                    module = %self.config.module_path,
                    timeout_ms = timeout.as_millis(),
                    "WASM plugin execution timed out"
                );
                Err(WasmError::Timeout {
                    timeout_ms: timeout.as_millis(),
                })
            })
    }

    fn epoch_deadline_ticks(&self) -> u64 {
        let ms = u64::try_from(self.config.timeout.as_millis()).unwrap_or(u64::MAX);
        ms.div_ceil(EPOCH_TICK_MS).max(1)
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_wasi_component(
        &self,
        pre: &ProxyPre<WasiHostState>,
        req: Request<Bytes>,
        is_https: bool,
    ) -> Result<WasmExecutionResult, WasmError> {
        let max_mem =
            usize::try_from(self.config.max_memory.as_bytes()).unwrap_or(16 * 1024 * 1024);
        let timeout_ms = self.config.timeout.as_millis();
        let limits = StoreLimitsBuilder::new()
            .memory_size(max_mem)
            .memories(1)
            .tables(8)
            .table_elements(10_000)
            .instances(4)
            .trap_on_grow_failure(true)
            .build();

        // Zero ambient capabilities: no preopened dirs, no env vars, no args, no sockets.
        let wasi = WasiCtx::builder().build();
        let mut http_ctx = WasiHttpCtx::new();
        http_ctx.set_field_size_limit(MAX_WASI_HTTP_FIELD_BYTES);
        let mut table = ResourceTable::new();
        table.set_max_capacity(MAX_WASI_RESOURCE_TABLE_CAPACITY);

        let state = WasiHostState {
            wasi,
            http: http_ctx,
            hooks: MiraServeHttpHooks {
                allow_outbound_hosts: Arc::new(self.config.allow_outbound_hosts.clone()),
            },
            table,
            limits,
        };

        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(self.config.max_fuel)
            .map_err(|err| WasmError::Trap(format!("failed to set WASM fuel: {err}")))?;
        store
            .fuel_async_yield_interval(Some(FUEL_ASYNC_YIELD_INTERVAL))
            .map_err(|err| WasmError::Trap(format!("failed to set fuel yield interval: {err}")))?;
        store.set_epoch_deadline(self.epoch_deadline_ticks());
        store.epoch_deadline_trap();

        let (parts, body_bytes) = req.into_parts();
        let hyper_req = Request::from_parts(parts, Full::new(body_bytes));
        let scheme = if is_https {
            WasiScheme::Https
        } else {
            WasiScheme::Http
        };

        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        let incoming_req = store
            .data_mut()
            .http()
            .new_incoming_request(scheme, hyper_req)
            .map_err(|err| WasmError::Trap(format!("wasi:http request setup failed: {err}")))?;
        let outparam = store
            .data_mut()
            .http()
            .new_response_outparam(resp_tx)
            .map_err(|err| WasmError::Trap(format!("wasi:http outparam setup failed: {err}")))?;

        let proxy = pre.instantiate_async(&mut store).await.map_err(|err| {
            classify_wasmtime_error(&err, self.config.max_fuel, max_mem, timeout_ms)
        })?;

        // Run guest handler CONCURRENTLY with bounded streaming response collection so
        // outgoing-body backpressure (buffer_chunks=1) never deadlocks AND host memory stays capped.
        let handle_fut = async move {
            let call_res = proxy
                .wasi_http_incoming_handler()
                .call_handle(&mut store, incoming_req, outparam)
                .await;
            let remaining_fuel = store.get_fuel().unwrap_or(0);
            let fuel_consumed = self.config.max_fuel.saturating_sub(remaining_fuel);
            // Explicitly drop store so outgoing response body stream closes cleanly at handler exit.
            drop(store);
            (call_res, fuel_consumed)
        };

        let collect_fut = async move {
            let wasi_resp = resp_rx
                .await
                .map_err(|_| {
                    WasmError::Trap(
                        "WASI HTTP component did not invoke response-outparam::set".to_owned(),
                    )
                })?
                .map_err(|err| WasmError::Trap(format!("wasi:http component error: {err:?}")))?;

            let (mut resp_parts, resp_body) = wasi_resp.into_parts();
            if resp_parts.status.is_informational() {
                return Err(WasmError::Trap(
                    "WASM plugin emitted forbidden 1xx informational status".to_owned(),
                ));
            }
            sanitize_plugin_response_headers(&mut resp_parts.headers);

            let collected = Limited::new(resp_body, MAX_PLUGIN_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|err| {
                    WasmError::Trap(format!(
                        "WASM response body exceeded {MAX_PLUGIN_RESPONSE_BYTES} byte cap or failed: {err:?}"
                    ))
                })?
                .to_bytes();

            Ok(Response::from_parts(resp_parts, collected))
        };

        let ((call_res, fuel_consumed), resp_res) = tokio::join!(handle_fut, collect_fut);
        if let Err(err) = call_res {
            return Err(classify_wasmtime_error(
                &err,
                self.config.max_fuel,
                max_mem,
                timeout_ms,
            ));
        }

        let response = resp_res?;
        Ok(WasmExecutionResult {
            response,
            fuel_consumed,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_core_module(
        &self,
        module: &Module,
        req: &Request<Bytes>,
    ) -> Result<WasmExecutionResult, WasmError> {
        let max_mem =
            usize::try_from(self.config.max_memory.as_bytes()).unwrap_or(16 * 1024 * 1024);
        let timeout_ms = self.config.timeout.as_millis();
        let limits = StoreLimitsBuilder::new()
            .memory_size(max_mem)
            .memories(1)
            .tables(4)
            .table_elements(10_000)
            .instances(2)
            .trap_on_grow_failure(true)
            .build();

        let method_bytes = req.method().as_str().as_bytes().to_vec();
        let path_bytes = req.uri().path().as_bytes().to_vec();

        let state = CoreHostState {
            limits,
            request_method: method_bytes.clone(),
            request_path: path_bytes.clone(),
            response_body: Vec::new(),
            response_headers: HeaderMap::new(),
        };

        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(self.config.max_fuel)
            .map_err(|err| WasmError::Trap(format!("failed to set WASM fuel: {err}")))?;
        store
            .fuel_async_yield_interval(Some(FUEL_ASYNC_YIELD_INTERVAL))
            .map_err(|err| WasmError::Trap(format!("failed to set fuel yield interval: {err}")))?;
        store.set_epoch_deadline(self.epoch_deadline_ticks());
        store.epoch_deadline_trap();

        let mut linker: CoreLinker<CoreHostState> = CoreLinker::new(&self.engine);

        // Safe pull host imports so guest modules can read request method/path into their own buffers.
        linker
            .func_wrap(
                "miraserve",
                "read_request_method",
                |mut caller: Caller<'_, CoreHostState>, ptr: i32, cap: i32| -> i32 {
                    copy_host_bytes_to_guest(&mut caller, ptr, cap, |s| &s.request_method)
                },
            )
            .map_err(|err| WasmError::Compile(err.to_string()))?;

        linker
            .func_wrap(
                "miraserve",
                "read_request_path",
                |mut caller: Caller<'_, CoreHostState>, ptr: i32, cap: i32| -> i32 {
                    copy_host_bytes_to_guest(&mut caller, ptr, cap, |s| &s.request_path)
                },
            )
            .map_err(|err| WasmError::Compile(err.to_string()))?;

        linker
            .func_wrap(
                "miraserve",
                "set_response_body",
                |mut caller: Caller<'_, CoreHostState>, ptr: i32, len: i32| -> i32 {
                    let (Ok(offset), Ok(size)) = (usize::try_from(ptr), usize::try_from(len))
                    else {
                        return -1;
                    };
                    if size > MAX_PLUGIN_RESPONSE_BYTES {
                        return -2;
                    }
                    if !charge_host_copy_fuel(&mut caller, size) {
                        return -8;
                    }
                    let Some(mem) = caller
                        .get_export("memory")
                        .and_then(wasmtime::Extern::into_memory)
                    else {
                        return -3;
                    };
                    let mut buf = vec![0_u8; size];
                    if mem.read(&caller, offset, &mut buf).is_err() {
                        return -4;
                    }
                    caller.data_mut().response_body = buf;
                    0
                },
            )
            .map_err(|err| WasmError::Compile(err.to_string()))?;

        linker
            .func_wrap(
                "miraserve",
                "set_response_header",
                |mut caller: Caller<'_, CoreHostState>,
                 k_ptr: i32,
                 k_len: i32,
                 v_ptr: i32,
                 v_len: i32|
                 -> i32 {
                    if caller.data().response_headers.len() >= MAX_PLUGIN_HEADERS {
                        return -1;
                    }
                    let (Ok(ko), Ok(kl), Ok(vo), Ok(vl)) = (
                        usize::try_from(k_ptr),
                        usize::try_from(k_len),
                        usize::try_from(v_ptr),
                        usize::try_from(v_len),
                    ) else {
                        return -2;
                    };
                    if kl > 256 || vl > 4096 {
                        return -3;
                    }
                    if !charge_host_copy_fuel(&mut caller, kl.saturating_add(vl)) {
                        return -8;
                    }
                    let Some(mem) = caller
                        .get_export("memory")
                        .and_then(wasmtime::Extern::into_memory)
                    else {
                        return -4;
                    };
                    let mut k_buf = vec![0_u8; kl];
                    let mut v_buf = vec![0_u8; vl];
                    if mem.read(&caller, ko, &mut k_buf).is_err()
                        || mem.read(&caller, vo, &mut v_buf).is_err()
                    {
                        return -5;
                    }
                    let (Ok(name), Ok(val)) = (
                        HeaderName::from_bytes(&k_buf),
                        HeaderValue::from_bytes(&v_buf),
                    ) else {
                        return -6;
                    };
                    // Reject framing, hop-by-hop, Host, and Alt-Svc headers outright!
                    if is_forbidden_plugin_response_header(&name) {
                        return -7;
                    }
                    caller.data_mut().response_headers.insert(name, val);
                    0
                },
            )
            .map_err(|err| WasmError::Compile(err.to_string()))?;

        let instance = linker
            .instantiate_async(&mut store, module)
            .await
            .map_err(|err| {
                classify_wasmtime_error(&err, self.config.max_fuel, max_mem, timeout_ms)
            })?;

        let memory = instance.get_memory(&mut store, "memory").ok_or_else(|| {
            WasmError::Trap("core WASM module missing required exported 'memory'".to_owned())
        })?;

        // Marshal method + path into a dedicated freshly grown scratch page ABOVE all guest
        // static/stack data (NEVER overwriting linear memory offset 0!), or via guest-exported
        // `miraserve_alloc(len) -> ptr` if provided. Fail closed on any allocation/write failure.
        let total_input = method_bytes.len().saturating_add(path_bytes.len());
        let (method_ptr, path_ptr) = if total_input == 0 {
            (0_i32, 0_i32)
        } else if let Ok(alloc_fn) =
            instance.get_typed_func::<i32, i32>(&mut store, "miraserve_alloc")
        {
            let alloc_len = i32::try_from(total_input)
                .map_err(|_| WasmError::Trap("request metadata length overflows i32".to_owned()))?;
            let base = alloc_fn
                .call_async(&mut store, alloc_len)
                .await
                .map_err(|err| {
                    classify_wasmtime_error(&err, self.config.max_fuel, max_mem, timeout_ms)
                })?;
            let base_usize = usize::try_from(base).map_err(|_| {
                WasmError::Trap("miraserve_alloc returned negative pointer".to_owned())
            })?;
            let p_usize = base_usize.saturating_add(method_bytes.len());
            memory
                .write(&mut store, base_usize, &method_bytes)
                .map_err(|err| {
                    WasmError::Trap(format!("failed writing method into guest memory: {err}"))
                })?;
            memory
                .write(&mut store, p_usize, &path_bytes)
                .map_err(|err| {
                    WasmError::Trap(format!("failed writing path into guest memory: {err}"))
                })?;
            let p_i32 = i32::try_from(p_usize)
                .map_err(|_| WasmError::Trap("guest path pointer overflows i32".to_owned()))?;
            (base, p_i32)
        } else {
            let pages_needed = u64::try_from(total_input.div_ceil(WASM_PAGE_BYTES)).unwrap_or(1);
            let old_pages = memory
                .grow(&mut store, pages_needed)
                .map_err(|_| WasmError::MemoryLimitExceeded { max_bytes: max_mem })?;
            let m_usize = usize::try_from(old_pages)
                .ok()
                .and_then(|p| p.checked_mul(WASM_PAGE_BYTES))
                .ok_or_else(|| {
                    WasmError::Trap("guest memory scratch offset overflow".to_owned())
                })?;
            let p_usize = m_usize.saturating_add(method_bytes.len());
            memory
                .write(&mut store, m_usize, &method_bytes)
                .map_err(|err| {
                    WasmError::Trap(format!("failed writing method into scratch page: {err}"))
                })?;
            memory
                .write(&mut store, p_usize, &path_bytes)
                .map_err(|err| {
                    WasmError::Trap(format!("failed writing path into scratch page: {err}"))
                })?;
            let m_i32 = i32::try_from(m_usize)
                .map_err(|_| WasmError::Trap("guest method pointer overflows i32".to_owned()))?;
            let p_i32 = i32::try_from(p_usize)
                .map_err(|_| WasmError::Trap("guest path pointer overflows i32".to_owned()))?;
            (m_i32, p_i32)
        };

        let handle_fn = instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "miraserve_handle")
            .map_err(|err| {
                WasmError::Compile(format!(
                    "core WASM module missing expected export 'miraserve_handle(i32,i32,i32,i32)->i32': {err}"
                ))
            })?;

        let raw_status = handle_fn
            .call_async(
                &mut store,
                (
                    method_ptr,
                    i32::try_from(method_bytes.len()).unwrap_or(0),
                    path_ptr,
                    i32::try_from(path_bytes.len()).unwrap_or(0),
                ),
            )
            .await
            .map_err(|err| {
                classify_wasmtime_error(&err, self.config.max_fuel, max_mem, timeout_ms)
            })?;

        let remaining_fuel = store.get_fuel().unwrap_or(0);
        let fuel_consumed = self.config.max_fuel.saturating_sub(remaining_fuel);

        let status = u16::try_from(raw_status)
            .ok()
            .filter(|code| !(100..200).contains(code))
            .and_then(|code| StatusCode::from_u16(code).ok())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        let mut data = store.into_data();
        sanitize_plugin_response_headers(&mut data.response_headers);
        let mut resp = Response::new(Bytes::from(data.response_body));
        *resp.status_mut() = status;
        *resp.headers_mut() = data.response_headers;

        Ok(WasmExecutionResult {
            response: resp,
            fuel_consumed,
        })
    }
}

fn copy_host_bytes_to_guest(
    caller: &mut Caller<'_, CoreHostState>,
    ptr: i32,
    cap: i32,
    extract: impl Fn(&CoreHostState) -> &[u8],
) -> i32 {
    let (Ok(offset), Ok(max_len)) = (usize::try_from(ptr), usize::try_from(cap)) else {
        return -1;
    };
    let bytes = extract(caller.data()).to_vec();
    let to_copy = bytes.len().min(max_len);
    if !charge_host_copy_fuel(caller, to_copy) {
        return -8;
    }
    let Some(mem) = caller
        .get_export("memory")
        .and_then(wasmtime::Extern::into_memory)
    else {
        return -3;
    };
    let Some(slice) = bytes.get(..to_copy) else {
        return -4;
    };
    if mem.write(caller, offset, slice).is_err() {
        return -4;
    }
    i32::try_from(to_copy).unwrap_or(-5)
}

/// Deducts proportional CPU fuel for host-side `memcpy` allocations so plugins cannot
/// perform repeated multi-megabyte host copies under a tiny fuel budget.
fn charge_host_copy_fuel(caller: &mut Caller<'_, CoreHostState>, byte_count: usize) -> bool {
    let cost = u64::try_from(byte_count / 64).unwrap_or(u64::MAX).max(1);
    let Ok(remaining) = caller.get_fuel() else {
        return true;
    };
    if remaining < cost {
        let _ = caller.set_fuel(0);
        return false;
    }
    caller.set_fuel(remaining.saturating_sub(cost)).is_ok()
}

/// Returns `true` for framing, hop-by-hop, `Host`, and `Alt-Svc` headers that sandboxed
/// WASM plugins MUST NOT emit (defeating response splitting and protocol downgrade attacks).
#[must_use]
pub fn is_forbidden_plugin_response_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "upgrade"
            | "te"
            | "trailer"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "http2-settings"
            | "host"
            | "alt-svc"
    )
}

fn sanitize_plugin_response_headers(headers: &mut HeaderMap) {
    let mut dynamic: Vec<HeaderName> = Vec::new();
    for val in headers.get_all(CONNECTION) {
        if let Ok(raw) = val.to_str() {
            for tok in raw.split(',') {
                if let Ok(hn) = HeaderName::from_bytes(tok.trim().as_bytes()) {
                    dynamic.push(hn);
                }
            }
        }
    }
    for name in dynamic {
        headers.remove(&name);
    }

    let forbidden_keys: Vec<HeaderName> = headers
        .keys()
        .filter(|name| is_forbidden_plugin_response_header(name))
        .cloned()
        .collect();
    for name in forbidden_keys {
        headers.remove(&name);
    }
}

struct CoreHostState {
    limits: StoreLimits,
    request_method: Vec<u8>,
    request_path: Vec<u8>,
    response_body: Vec<u8>,
    response_headers: HeaderMap,
}

struct WasiHostState {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    hooks: MiraServeHttpHooks,
    table: ResourceTable,
    limits: StoreLimits,
}

impl WasiView for WasiHostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for WasiHostState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.hooks,
        }
    }
}

/// Zero-ambient outbound HTTP hook + strict outgoing-body chunk limits for `wasi:http`
/// components (Threat Model T7).
struct MiraServeHttpHooks {
    allow_outbound_hosts: Arc<Vec<String>>,
}

impl WasiHttpHooks for MiraServeHttpHooks {
    fn p2_outgoing_body_buffer_chunks(&mut self) -> usize {
        WASI_OUTGOING_BODY_BUFFER_CHUNKS
    }

    fn p2_outgoing_body_chunk_size(&mut self) -> usize {
        WASI_OUTGOING_BODY_CHUNK_BYTES
    }

    fn send_request(
        &mut self,
        request: http::Request<WasiBody>,
        _options: Option<RequestOptions>,
        _fut: Box<dyn Future<Output = Result<(), WasiHttpError>> + Send>,
    ) -> Box<
        dyn Future<
                Output = Result<
                    (
                        http::Response<WasiBody>,
                        Box<dyn Future<Output = Result<(), WasiHttpError>> + Send>,
                    ),
                    WasiHttpError,
                >,
            > + Send,
    > {
        let host = request
            .uri()
            .host()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let allowed = self
            .allow_outbound_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&host));
        Box::new(async move {
            if !allowed {
                warn!(host = %host, "blocked unauthorized outbound HTTP request from WASM plugin");
                return Err(WasiHttpError::HttpRequestDenied);
            }
            // Outbound proxying requires explicit future host proxy wiring; fail closed until enabled.
            Err(WasiHttpError::HttpRequestDenied)
        })
    }
}

/// Detects whether `bytes` represent a WebAssembly Component Model artifact vs a Core Module.
fn is_component_source(bytes: &[u8]) -> bool {
    // Binary Component Model header: `\0asm` followed by layer/version `0x0d 0x00 0x01 0x00`.
    if bytes.len() >= 8 && bytes.get(..8) == Some(b"\0asm\x0d\x00\x01\x00") {
        return true;
    }
    // Text WAT component starts with `(component`.
    if let Ok(text) = std::str::from_utf8(bytes) {
        let trimmed = text.trim_start();
        if trimmed.starts_with("(component") {
            return true;
        }
    }
    false
}

fn classify_wasmtime_error(
    err: &wasmtime::Error,
    fuel_budget: u64,
    max_memory_bytes: usize,
    timeout_ms: u128,
) -> WasmError {
    if let Some(trap) = err.downcast_ref::<Trap>() {
        if *trap == Trap::OutOfFuel {
            return WasmError::FuelExhausted {
                budget: fuel_budget,
            };
        }
        if *trap == Trap::Interrupt {
            return WasmError::Timeout { timeout_ms };
        }
        return WasmError::Trap(format!("{trap}"));
    }
    let msg = err.to_string();
    let full_chain = format!("{err:?}").to_ascii_lowercase();
    if full_chain.contains("out of fuel") || full_chain.contains("all fuel consumed") {
        return WasmError::FuelExhausted {
            budget: fuel_budget,
        };
    }
    if full_chain.contains("epoch") || full_chain.contains("interrupt") {
        return WasmError::Timeout { timeout_ms };
    }
    if full_chain.contains("memory")
        && (full_chain.contains("limit")
            || full_chain.contains("grow")
            || full_chain.contains("minimum")
            || full_chain.contains("exceed"))
    {
        return WasmError::MemoryLimitExceeded {
            max_bytes: max_memory_bytes,
        };
    }
    WasmError::Trap(msg)
}
