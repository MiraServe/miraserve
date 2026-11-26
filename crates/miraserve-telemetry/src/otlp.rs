//! Standalone Prometheus scrape HTTP server and OTLP/HTTP JSON metrics exporter.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::service::service_fn;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use miraserve_tls::build_upstream_client_config;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tracing::{info, warn};

use crate::TelemetryError;
use crate::metrics::TelemetryRegistry;

/// Prometheus text exposition format 0.0.4 media type.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Maximum concurrent connections accepted by the Prometheus metrics listener.
const MAX_METRICS_CONNECTIONS: usize = 32;

/// Maximum header buffer size for HTTP/1.1 metrics scrape requests.
const MAX_METRICS_HEADER_BUF: usize = 16 * 1024;

/// Maximum time allowed to read HTTP headers on a metrics scrape connection.
const METRICS_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum total wall-clock time for a single metrics scrape connection.
const METRICS_CONN_TIMEOUT: Duration = Duration::from_secs(10);

/// Backoff duration after a transient accept error on the metrics listener.
const METRICS_ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(25);

/// Connect timeout for outbound OTLP collector connections.
const OTLP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// End-to-end request timeout for a single OTLP batch export.
const OTLP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum OTLP collector response body bytes drained to allow connection reuse.
const MAX_OTLP_RESPONSE_DRAIN_BYTES: usize = 64 * 1024;

/// Handle to a running Prometheus metrics HTTP listener.
pub struct RunningMetricsServer {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for RunningMetricsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningMetricsServer")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl RunningMetricsServer {
    /// Returns the actual bound socket address (resolving ephemeral port `0`).
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Gracefully stops the Prometheus metrics listener.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }
}

/// Lightweight dedicated HTTP/1.1 listener serving Prometheus exposition metrics.
#[derive(Debug)]
pub struct MetricsServer;

impl MetricsServer {
    /// Starts serving Prometheus metrics on `bind_addr` at `metrics_path` (e.g. `"/metrics"`).
    ///
    /// # Errors
    /// Returns [`TelemetryError::Io`] if binding `bind_addr` fails.
    pub async fn start(
        bind_addr: SocketAddr,
        metrics_path: String,
        registry: Arc<TelemetryRegistry>,
    ) -> Result<RunningMetricsServer, TelemetryError> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(TelemetryError::Io)?;
        let local_addr = listener.local_addr().map_err(TelemetryError::Io)?;
        let path_arc = Arc::new(metrics_path);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        info!(addr = %local_addr, path = %path_arc, "Prometheus metrics listener started");

        let conn_sem = Arc::new(Semaphore::new(MAX_METRICS_CONNECTIONS));
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                                    warn!("metrics listener connection limit reached; dropping connection");
                                    drop(stream);
                                    continue;
                                };
                                let reg = Arc::clone(&registry);
                                let expected_path = Arc::clone(&path_arc);
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let io = TokioIo::new(stream);
                                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                                        let reg = Arc::clone(&reg);
                                        let expected = Arc::clone(&expected_path);
                                        async move {
                                            Ok::<_, std::convert::Infallible>(
                                                handle_metrics_request(&req, &expected, &reg),
                                            )
                                        }
                                    });
                                    let mut h1 = hyper::server::conn::http1::Builder::new();
                                    h1.timer(TokioTimer::new())
                                        .header_read_timeout(METRICS_HEADER_READ_TIMEOUT)
                                        .keep_alive(false)
                                        .max_buf_size(MAX_METRICS_HEADER_BUF);
                                    let _ = tokio::time::timeout(
                                        METRICS_CONN_TIMEOUT,
                                        h1.serve_connection(io, svc),
                                    )
                                    .await;
                                });
                            }
                            Err(err) => {
                                warn!(error = %err, "metrics listener accept error");
                                tokio::time::sleep(METRICS_ACCEPT_ERROR_BACKOFF).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(RunningMetricsServer {
            local_addr,
            shutdown_tx,
            task,
        })
    }
}

fn handle_metrics_request<B>(
    req: &Request<B>,
    metrics_path: &str,
    registry: &TelemetryRegistry,
) -> Response<Full<Bytes>> {
    if req.uri().path() != metrics_path {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(b"404 Not Found\n")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
    }
    if *req.method() != Method::GET && *req.method() != Method::HEAD {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(b"405 Method Not Allowed\n")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
    }
    let body = if *req.method() == Method::HEAD {
        Bytes::new()
    } else {
        Bytes::from(registry.render_prometheus())
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)
        .body(Full::new(body))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// OTLP/HTTP v1 JSON metrics exporter using `hyper-rustls` + `aws-lc-rs` PQC TLS.
#[derive(Clone)]
pub struct OtlpExporter {
    metrics_url: String,
    service_name: String,
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl std::fmt::Debug for OtlpExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpExporter")
            .field("metrics_url", &self.metrics_url)
            .field("service_name", &self.service_name)
            .finish_non_exhaustive()
    }
}

impl OtlpExporter {
    /// Creates an [`OtlpExporter`] targeting `base_endpoint` (appending `/v1/metrics` if needed).
    ///
    /// # Errors
    /// Returns [`TelemetryError::Tls`] if the TLS client config fails to initialize.
    pub fn new(
        base_endpoint: &str,
        service_name: impl Into<String>,
    ) -> Result<Self, TelemetryError> {
        let trimmed = base_endpoint.trim_end_matches('/');
        let metrics_url = if trimmed.ends_with("/v1/metrics") {
            trimmed.to_owned()
        } else {
            format!("{trimmed}/v1/metrics")
        };

        let tls_cfg = build_upstream_client_config(None)
            .map_err(|err| TelemetryError::Tls(err.to_string()))?;
        let mut http_conn = HttpConnector::new();
        http_conn.enforce_http(false);
        http_conn.set_connect_timeout(Some(OTLP_CONNECT_TIMEOUT));
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_cfg)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_conn);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build(https);

        Ok(Self {
            metrics_url,
            service_name: service_name.into(),
            client,
        })
    }

    /// Exports one OTLP/HTTP JSON metrics batch from `registry` to the configured collector.
    ///
    /// # Errors
    /// Returns [`TelemetryError::Export`] if HTTP delivery fails or the collector rejects it.
    pub async fn export_once(
        &self,
        registry: &TelemetryRegistry,
    ) -> Result<StatusCode, TelemetryError> {
        let payload = registry.to_otlp_metrics_json(&self.service_name);
        let bytes = serde_json::to_vec(&payload)
            .map_err(|err| TelemetryError::Export(format!("OTLP JSON serialize failed: {err}")))?;

        let req = Request::builder()
            .method(Method::POST)
            .uri(&self.metrics_url)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|err| TelemetryError::Export(format!("invalid OTLP request: {err}")))?;

        let resp = tokio::time::timeout(OTLP_REQUEST_TIMEOUT, self.client.request(req))
            .await
            .map_err(|_| {
                TelemetryError::Export(format!(
                    "OTLP HTTP POST timed out after {}s",
                    OTLP_REQUEST_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|err| TelemetryError::Export(format!("OTLP HTTP POST failed: {err}")))?;
        let status = resp.status();
        // Bound response body drain so a malicious/misbehaving collector cannot cause OOM or hang.
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            Limited::new(resp.into_body(), MAX_OTLP_RESPONSE_DRAIN_BYTES).collect(),
        )
        .await;
        if !status.is_success() {
            return Err(TelemetryError::Export(format!(
                "OTLP collector returned non-success status {status}"
            )));
        }
        Ok(status)
    }

    /// Runs a periodic background OTLP/HTTP JSON metrics push loop until `shutdown` signals
    /// (`true` or channel closed), performing a best-effort final flush on shutdown (`TEL-1`).
    pub async fn run_export_loop(
        self,
        registry: Arc<TelemetryRegistry>,
        interval: Duration,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let cadence = interval.max(Duration::from_secs(1));
        let mut ticker = tokio::time::interval(cadence);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate zero-delay tick so startup metrics accumulate first.
        ticker.tick().await;

        info!(
            endpoint = %self.metrics_url,
            service = %self.service_name,
            interval_secs = cadence.as_secs(),
            "OTLP/HTTP background metrics exporter started"
        );

        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        if let Err(err) = self.export_once(&registry).await {
                            warn!(error = %err, endpoint = %self.metrics_url, "final OTLP metrics flush failed");
                        }
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(err) = self.export_once(&registry).await {
                        warn!(error = %err, endpoint = %self.metrics_url, "periodic OTLP metrics export failed");
                    }
                }
            }
        }
    }
}
