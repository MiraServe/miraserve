//! Threat Model T7 security & isolation tests for `miraserve-wasm`:
//! - Normal HTTP plugin response headers/body + deterministic CPU fuel metering
//! - Infinite loop DoS defense (`WasmError::FuelExhausted`)
//! - Linear memory ceiling enforcement (`StoreLimits` blocking memory bombs)
//! - Zero ambient filesystem/env capability enforcement

use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use miraserve_config::{ByteSize, WasmPluginConfig};
use miraserve_wasm::{WasmError, WasmPluginRuntime};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn base_config(max_mem_bytes: u64, max_fuel: u64) -> WasmPluginConfig {
    WasmPluginConfig {
        module_path: "<inline-test.wat>".to_owned(),
        max_memory: ByteSize::from_bytes(max_mem_bytes),
        max_fuel,
        timeout: Duration::from_secs(2),
        allow_outbound_hosts: Vec::new(),
    }
}

#[tokio::test]
async fn sandboxed_wasm_plugin_returns_http_response_headers_and_fuel() -> TestResult {
    let wat = r#"
(module
  (import "miraserve" "set_response_body" (func $set_body (param i32 i32) (result i32)))
  (import "miraserve" "set_response_header" (func $set_hdr (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "Hello from MiraServe WASM!")
  (data (i32.const 1100) "x-wasm-plugin")
  (data (i32.const 1120) "miraserve-sandbox")
  (func (export "miraserve_handle") (param $m_ptr i32) (param $m_len i32) (param $p_ptr i32) (param $p_len i32) (result i32)
    (drop (call $set_hdr (i32.const 1100) (i32.const 13) (i32.const 1120) (i32.const 17)))
    (drop (call $set_body (i32.const 1024) (i32.const 26)))
    (i32.const 200)
  )
)
"#;

    let runtime = WasmPluginRuntime::from_bytes(base_config(1024 * 1024, 500_000), wat.as_bytes())?;
    let req = Request::builder().uri("/edge/hello").body(Bytes::new())?;

    let result = runtime.execute(req, true).await?;
    assert_eq!(result.response.status(), StatusCode::OK);
    assert_eq!(
        result
            .response
            .headers()
            .get("x-wasm-plugin")
            .and_then(|v| v.to_str().ok()),
        Some("miraserve-sandbox")
    );
    assert_eq!(
        result.response.body().as_ref(),
        b"Hello from MiraServe WASM!"
    );
    assert!(result.fuel_consumed > 0 && result.fuel_consumed < 500_000);
    Ok(())
}

#[tokio::test]
async fn infinite_loop_plugin_is_terminated_deterministically_by_fuel_limit() -> TestResult {
    let infinite_loop_wat = r#"
(module
  (memory (export "memory") 1)
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (loop $spin
      (br $spin)
    )
    (i32.const 200)
  )
)
"#;

    let runtime = WasmPluginRuntime::from_bytes(
        base_config(1024 * 1024, 25_000),
        infinite_loop_wat.as_bytes(),
    )?;
    let req = Request::builder().uri("/edge/dos").body(Bytes::new())?;

    let err = runtime.execute(req, true).await;
    assert!(
        matches!(err, Err(WasmError::FuelExhausted { budget: 25_000 })),
        "expected FuelExhausted, got: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn memory_bomb_plugin_is_blocked_by_store_limits() -> TestResult {
    // 1. Dynamic memory.grow beyond 256 KiB (4 Wasm pages) returns -1!
    let grow_bomb_wat = r#"
(module
  (memory (export "memory") 1)
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    ;; Try allocating 100 pages (6.4 MiB) when max-memory is 256 KiB (4 pages)
    (if (result i32) (i32.eq (memory.grow (i32.const 100)) (i32.const -1))
      (then (i32.const 503))
      (else (i32.const 200))
    )
  )
)
"#;
    let runtime_grow =
        WasmPluginRuntime::from_bytes(base_config(256 * 1024, 500_000), grow_bomb_wat.as_bytes())?;
    let grow_res = runtime_grow
        .execute(Request::builder().uri("/grow").body(Bytes::new())?, true)
        .await;
    assert!(
        matches!(grow_res, Err(WasmError::MemoryLimitExceeded { .. })),
        "memory.grow exceeding max_memory must trap with MemoryLimitExceeded (trap_on_grow_failure=true), got: {grow_res:?}"
    );

    // 2. Static initial memory declaration (100 pages = 6.4 MiB) exceeding 256 KiB fails instantiation!
    let static_bomb_wat = r#"
(module
  (memory (export "memory") 100)
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (i32.const 200)
  )
)
"#;
    let runtime_static = WasmPluginRuntime::from_bytes(
        base_config(256 * 1024, 500_000),
        static_bomb_wat.as_bytes(),
    )?;
    let err = runtime_static
        .execute(
            Request::builder().uri("/static-bomb").body(Bytes::new())?,
            true,
        )
        .await;
    assert!(
        matches!(err, Err(WasmError::MemoryLimitExceeded { .. })),
        "expected MemoryLimitExceeded, got: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn ambient_filesystem_import_is_denied_in_sandbox() -> TestResult {
    let evil_fs_wat = r#"
(module
  (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (i32.const 200)
  )
)
"#;
    let runtime =
        WasmPluginRuntime::from_bytes(base_config(1024 * 1024, 500_000), evil_fs_wat.as_bytes())?;
    let err = runtime
        .execute(
            Request::builder().uri("/fs-escape").body(Bytes::new())?,
            true,
        )
        .await;
    assert!(
        err.is_err(),
        "plugin importing host filesystem API must be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn wasm_audit_regressions_epoch_timeout_header_hygiene_and_offset0_preservation() -> TestResult
{
    // 1. Preemptive epoch interruption enforces tight wall-clock timeout even with huge fuel budget!
    let spin_wat = r#"
(module
  (memory (export "memory") 1)
  (func (export "miraserve_handle") (param i32 i32 i32 i32) (result i32)
    (loop $spin (br $spin))
    (i32.const 200)
  )
)
"#;
    let timeout_cfg = WasmPluginConfig {
        module_path: "<timeout-test.wat>".to_owned(),
        max_memory: ByteSize::from_bytes(1024 * 1024),
        // Give enough fuel (~several seconds of tight JIT loop even on fast Linux CPUs) so the
        // 60ms preemptive epoch interruption ALWAYS wins deterministically over FuelExhausted.
        max_fuel: 5_000_000_000,
        timeout: Duration::from_millis(60),
        allow_outbound_hosts: Vec::new(),
    };
    let rt_timeout = WasmPluginRuntime::from_bytes(timeout_cfg, spin_wat.as_bytes())?;
    let err = rt_timeout
        .execute(Request::builder().uri("/spin").body(Bytes::new())?, true)
        .await;
    assert!(
        matches!(err, Err(WasmError::Timeout { .. })),
        "expected epoch Timeout before 50M fuel exhaustion, got: {err:?}"
    );

    // 2. Offset-0 static guest data MUST NOT be clobbered by request marshaling, AND forbidden
    //    framing/Alt-Svc headers are rejected (`set_response_header` returns -7)!
    let hygiene_wat = r#"
(module
  (import "miraserve" "set_response_body" (func $set_body (param i32 i32) (result i32)))
  (import "miraserve" "set_response_header" (func $set_hdr (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; Static data placed right at offset 0 — would be clobbered by naive offset-0 writes!
  (data (i32.const 0) "INTACT_OFFSET0_DATA!")
  (data (i32.const 64) "transfer-encoding")
  (data (i32.const 96) "chunked")
  (data (i32.const 128) "alt-svc")
  (data (i32.const 160) "h3=\":9999\"")
  (data (i32.const 200) "x-safe")
  (data (i32.const 220) "ok")
  (func (export "miraserve_handle") (param $m_ptr i32) (param $m_len i32) (param $p_ptr i32) (param $p_len i32) (result i32)
    ;; Attempt to set forbidden Transfer-Encoding and Alt-Svc headers -> both ignored/rejected
    (drop (call $set_hdr (i32.const 64) (i32.const 17) (i32.const 96) (i32.const 7)))
    (drop (call $set_hdr (i32.const 128) (i32.const 7) (i32.const 160) (i32.const 10)))
    ;; Safe header succeeds
    (drop (call $set_hdr (i32.const 200) (i32.const 6) (i32.const 220) (i32.const 2)))
    ;; Echo bytes at offset 0 to prove host marshaling did NOT overwrite static data!
    (drop (call $set_body (i32.const 0) (i32.const 20)))
    (i32.const 200)
  )
)
"#;
    let rt_hygiene =
        WasmPluginRuntime::from_bytes(base_config(1024 * 1024, 500_000), hygiene_wat.as_bytes())?;
    let res = rt_hygiene
        .execute(
            Request::builder()
                .uri("/long/path/that/would/clobber/offset/zero")
                .body(Bytes::new())?,
            true,
        )
        .await?;
    assert_eq!(res.response.status(), StatusCode::OK);
    assert_eq!(res.response.body().as_ref(), b"INTACT_OFFSET0_DATA!");
    assert!(res.response.headers().get("transfer-encoding").is_none());
    assert!(res.response.headers().get("alt-svc").is_none());
    assert_eq!(
        res.response
            .headers()
            .get("x-safe")
            .and_then(|v| v.to_str().ok()),
        Some("ok")
    );
    Ok(())
}
