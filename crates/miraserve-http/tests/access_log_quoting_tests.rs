//! Access-log field quoting tests: client-supplied fields (`host`, `method`, `target`,
//! `user_agent`, `referer`) must reach the logger as string values so the formatter quotes and
//! escapes embedded spaces and quotes instead of allowing forged `key=value` tokens.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miraserve_config::parse_kdl;
use miraserve_http::HttpEngine;
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber, span};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Recorder {
    values: BTreeMap<String, String>,
    /// Fields that arrived as string values (quoted and escaped by the standard formatter).
    as_str: BTreeSet<String>,
}

impl Visit for Recorder {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.values
            .insert(field.name().to_owned(), value.to_owned());
        self.as_str.insert(field.name().to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.values
            .insert(field.name().to_owned(), format!("{value:?}"));
    }
}

/// One access-log line: its field values, and which fields arrived as string values.
type Line = (BTreeMap<String, String>, BTreeSet<String>);

#[derive(Clone, Default)]
struct AccessCapture {
    lines: Arc<Mutex<Vec<Line>>>,
}

impl Subscriber for AccessCapture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != "miraserve::access" {
            return;
        }
        let mut rec = Recorder::default();
        event.record(&mut rec);
        if let Ok(mut lines) = self.lines.lock() {
            lines.push((rec.values, rec.as_str));
        }
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

#[tokio::test(flavor = "current_thread")]
async fn client_supplied_access_log_fields_are_string_values_so_they_get_quoted() -> TestResult {
    let capture = AccessCapture::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    let root = std::env::temp_dir().join(format!("miraserve-logq-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("hello.txt"), b"hi")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "logq.example.test" {{
    root "{}"
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("logq.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.7:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let serve = tokio::spawn(engine.serve_hyper_connection(
        server,
        peer,
        local,
        true,
        false,
        None,
        shutdown_rx,
    ));

    let forged_ua = "x\" status=500 host=victim.test completed=true";
    let forged_referer = "https://ref.example/x y status=403";
    let request = format!(
        "GET /hello.txt HTTP/1.1\r\nHost: logq.example.test\r\nUser-Agent: {forged_ua}\r\nReferer: {forged_referer}\r\nConnection: close\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await?;
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    let _ = tokio::time::timeout(Duration::from_secs(5), serve).await;

    let lines = capture.lines.lock().map_err(|_| "capture lock")?.clone();
    let (values, as_str) = lines.first().ok_or("no access log line was written")?;
    for field in ["host", "method", "target", "user_agent", "referer"] {
        assert!(
            as_str.contains(field),
            "access-log field '{field}' must be a string value so the formatter quotes it; \
             string fields were {as_str:?}"
        );
    }
    // The values themselves are intact (redaction aside) and the real fields are not overridden.
    assert_eq!(values.get("status").map(String::as_str), Some("200"));
    assert_eq!(
        values.get("host").map(String::as_str),
        Some("logq.example.test")
    );
    // What the standard formatter prints for a string value: quoted, inner quotes escaped.
    let printed = format!("{:?}", values.get("user_agent").map_or("", String::as_str));
    assert!(printed.starts_with('"') && printed.ends_with('"'));
    assert!(
        !printed.trim_matches('"').contains("\" status=500") || printed.contains("\\\""),
        "an embedded quote must be escaped: {printed}"
    );
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
