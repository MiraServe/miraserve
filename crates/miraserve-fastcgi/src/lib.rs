#![forbid(unsafe_code)]
//! Pure-Rust async FastCGI v1.0 client for isolated PHP-FPM / WordPress execution.
//!
//! Runs PHP strictly out-of-process over Unix domain sockets or TCP with zero C/PHP code
//! inside MiraServe's address space (Threat Model T5).

pub mod cgi;
pub mod protocol;

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, Method, Response, Version};
use miraserve_config::FastCgiTarget;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tracing::warn;

use crate::cgi::parse_cgi_bytes;
use crate::protocol::{
    EndRequestBody, RecordType, encode_begin_request, encode_params, read_record, write_record,
    write_stream_records,
};

/// Default FastCGI request execution timeout (30 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum buffered FastCGI stdout response size (32 MiB) to prevent OOM.
const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Errors produced by [`FastCgiClient`].
#[derive(Debug, Error)]
pub enum FastCgiError {
    /// Underlying socket I/O error.
    #[error("FastCGI transport I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// FastCGI wire protocol violation or framing error.
    #[error("FastCGI protocol error: {0}")]
    Protocol(String),
    /// Malformed CGI/1.1 headers emitted by the backend script.
    #[error("invalid CGI response from backend: {0}")]
    InvalidCgiResponse(String),
    /// Upstream execution exceeded configured timeout.
    #[error("FastCGI request timed out")]
    Timeout,
    /// The caller has no room to buffer more of the answer (see
    /// [`FastCgiClient::execute_reserving`]).
    #[error("no room to buffer the FastCGI answer")]
    NoRoom,
    /// Script path failed confinement validation.
    #[error("unsafe FastCGI script path '{0}'")]
    UnsafeScriptPath(String),
    /// Unix sockets requested on an unsupported platform.
    #[error("Unix domain socket FastCGI target '{0}' is only supported on Unix platforms")]
    UnsupportedTransport(String),
}

/// Request metadata passed to [`FastCgiClient::execute`].
#[derive(Debug, Clone)]
pub struct FastCgiRequest<'a> {
    /// HTTP method (`GET`, `POST`, etc.).
    pub method: &'a Method,
    /// HTTP protocol version (`HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`).
    pub version: Version,
    /// Script path relative to document root (e.g. `"/index.php"` or `"/wp-login.php"`).
    pub script_name: &'a str,
    /// Optional trailing `PATH_INFO` segment after the script name (e.g. `"/extra"` for
    /// `"/script.php/extra"`). When empty, `PATH_INFO` is omitted per RFC 3875 §4.1.5.
    pub path_info: &'a str,
    /// Original full request URI path + optional query (e.g. `"/blog/post-1?page=2"`).
    pub request_uri: &'a str,
    /// Query string without leading `?`.
    pub query_string: &'a str,
    /// Virtual host name (`SERVER_NAME`).
    pub server_name: &'a str,
    /// Local listener IP address (`SERVER_ADDR`), if available.
    pub server_addr: Option<IpAddr>,
    /// Local listener port (`SERVER_PORT`).
    pub server_port: u16,
    /// Client peer IP address (`REMOTE_ADDR`).
    pub client_ip: Option<IpAddr>,
    /// Client peer TCP/UDP port (`REMOTE_PORT`), if available.
    pub remote_port: Option<u16>,
    /// Whether the original client request used HTTPS.
    pub is_https: bool,
    /// Original HTTP request headers.
    pub headers: &'a HeaderMap,
    /// Request body payload forwarded over `FCGI_STDIN`.
    pub body: &'a [u8],
}

/// Pure-Rust async FastCGI v1.0 client targeting a PHP-FPM Unix socket or TCP pool.
#[derive(Debug, Clone)]
pub struct FastCgiClient {
    target: FastCgiTarget,
    document_root: PathBuf,
    timeout: Duration,
    max_response_bytes: usize,
    replay_safe_methods: bool,
    max_streamed_answers: Option<u32>,
}

/// What the backend answered (see [`FastCgiClient::execute_streaming`]).
pub enum FastCgiAnswer {
    /// The whole answer, read and buffered.
    Whole(Response<Bytes>),
    /// An answer larger than the buffer limit: its head and the first part of its body (as
    /// much as the limit), and the rest, still to be read from the backend. The response has
    /// a `Content-Length` only when the backend declared one that fits what it has sent so
    /// far; the tail then gives exactly the bytes that are left of it.
    Streamed(Response<Bytes>, AnswerTail),
}

/// The rest of an answer that did not fit the buffer limit. It holds the connection to the
/// backend, and so one of its workers, until it has been read to the end or is dropped.
pub struct AnswerTail {
    reader: Box<dyn AsyncRead + Send + Sync + Unpin>,
    /// Kept open: closing our side early could end the backend's request.
    _writer: Box<dyn Send + Sync>,
    /// The record that did not fit the buffer.
    pending: Option<Bytes>,
    /// What is left of the length the backend declared, when it declared one.
    remaining: Option<u64>,
    /// The longest wait for the backend's next record.
    idle: Duration,
    stderr: Vec<u8>,
    unmatched_records: u32,
    done: bool,
    /// Set by the first error: the connection is then in no known state, and every later
    /// call fails too.
    failed: bool,
}

impl std::fmt::Debug for AnswerTail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnswerTail")
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl AnswerTail {
    /// The next part of the body; `None` after the backend has ended the request properly.
    ///
    /// # Errors
    /// [`FastCgiError::Timeout`] when the backend sends no more of the body (and does not end
    /// the request) for the client's timeout, and
    /// the transport and protocol errors of [`FastCgiClient::execute`]. After an error the
    /// answer is incomplete and must not be presented as whole.
    pub async fn next(&mut self) -> Result<Option<Bytes>, FastCgiError> {
        // One deadline for the next part of the body or the end of the request: records that
        // carry neither (the backend's standard error, other request ids) do not extend it.
        if self.failed {
            return Err(FastCgiError::Protocol(
                "the FastCGI answer has already failed".to_owned(),
            ));
        }
        let idle = self.idle;
        let part = tokio::time::timeout(idle, self.next_part())
            .await
            .map_err(|_| FastCgiError::Timeout)
            .and_then(|part| part);
        if part.is_err() {
            self.failed = true;
            // What the script wrote to its standard error is most useful exactly now.
            if !self.stderr.is_empty() {
                let clean_stderr: String = String::from_utf8_lossy(&self.stderr)
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect();
                warn!(stderr = %clean_stderr, "FastCGI backend wrote to stderr before its answer failed");
                self.stderr.clear();
            }
        }
        part
    }

    async fn next_part(&mut self) -> Result<Option<Bytes>, FastCgiError> {
        if let Some(first) = self.pending.take() {
            return Ok(self.within_declared(first));
        }
        // All of a declared length has been given: the answer is complete, and whatever the
        // backend sends beyond it is not part of it.
        if self.remaining == Some(0) {
            self.done = true;
        }
        if self.done {
            return Ok(None);
        }
        loop {
            let rec = read_record(&mut self.reader).await?;
            if rec.request_id != REQUEST_ID {
                self.unmatched_records = self.unmatched_records.saturating_add(1);
                if self.unmatched_records > MAX_UNMATCHED_RECORDS {
                    return Err(FastCgiError::Protocol(
                        "FastCGI backend sent excessive records with mismatched request_id"
                            .to_owned(),
                    ));
                }
                continue;
            }
            match rec.record_type {
                RecordType::Stdout if !rec.content.is_empty() => {
                    return Ok(self.within_declared(Bytes::from(rec.content)));
                }
                RecordType::Stderr => keep_stderr(&mut self.stderr, &rec.content),
                RecordType::EndRequest => {
                    // Logged there, once: not again by the caller if the request ended badly.
                    let stderr = std::mem::take(&mut self.stderr);
                    end_of_request(&rec.content, &stderr)?;
                    self.done = true;
                    if let Some(missing) = self.remaining.filter(|left| *left > 0) {
                        return Err(FastCgiError::Protocol(format!(
                            "FastCGI answer ended {missing} bytes before its declared length"
                        )));
                    }
                    return Ok(None);
                }
                _ => {}
            }
        }
    }
}

impl AnswerTail {
    /// `part`, cut to what is left of a declared length.
    fn within_declared(&mut self, part: Bytes) -> Option<Bytes> {
        let Some(left) = self.remaining else {
            return Some(part);
        };
        let take = usize::try_from(left).map_or(part.len(), |left| left.min(part.len()));
        self.remaining = Some(left.saturating_sub(take as u64));
        if take == 0 {
            self.done = true;
            return None;
        }
        Some(part.slice(..take))
    }
}

/// How one attempt to reach the backend ended without a response.
enum AttemptError {
    /// The connection could not be made: the backend never saw the request.
    Connect(std::io::Error),
    /// The request was handed over (at least in part) before the failure.
    Exchange(FastCgiError),
}

impl FastCgiClient {
    /// Creates a new [`FastCgiClient`] targeting `target` with scripts confined to `document_root`.
    #[must_use]
    pub fn new(target: FastCgiTarget, document_root: impl Into<PathBuf>) -> Self {
        Self {
            target,
            document_root: document_root.into(),
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            replay_safe_methods: false,
            max_streamed_answers: None,
        }
    }

    /// Sets this backend's own limit of answers streaming at once (see
    /// [`Self::max_streamed_answers`]).
    #[must_use]
    pub const fn with_max_streamed_answers(mut self, max: Option<u32>) -> Self {
        self.max_streamed_answers = max;
        self
    }

    /// How many answers larger than the buffer this backend may have streaming at once, when
    /// its route sets a number of its own; the caller's general limit applies otherwise.
    #[must_use]
    pub const fn max_streamed_answers(&self) -> Option<u32> {
        self.max_streamed_answers
    }

    /// A name for the backend this client talks to, the same for every client of that
    /// backend: for limits that are per backend.
    #[must_use]
    pub fn backend_key(&self) -> String {
        match &self.target {
            // Spellings that name the same path as text count as one backend: empty and `.`
            // components are left out. Two different paths to one socket (a symbolic link)
            // are two backends here; configure one spelling per pool.
            FastCgiTarget::Unix { path } => {
                let parts: Vec<&str> = path
                    .split('/')
                    .filter(|part| !part.is_empty() && *part != ".")
                    .collect();
                format!("unix:/{}", parts.join("/"))
            }
            FastCgiTarget::Tcp { host, port } => {
                format!("tcp://{}:{port}", host.to_ascii_lowercase())
            }
        }
    }

    /// Allows a `GET`, `HEAD` or `OPTIONS` request to be sent a second time when the connection
    /// is lost after the request was handed to the backend (see [`Self::execute`]).
    #[must_use]
    pub const fn with_replay_safe_methods(mut self, replay: bool) -> Self {
        self.replay_safe_methods = replay;
        self
    }

    /// Overrides the per-request execution timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Executes a single FastCGI responder round-trip against PHP-FPM.
    ///
    /// # Errors
    /// Returns [`FastCgiError`] on unsafe script path, connection failure, timeout,
    /// wire protocol violation, or invalid CGI headers.
    pub async fn execute(&self, req: &FastCgiRequest<'_>) -> Result<Response<Bytes>, FastCgiError> {
        self.execute_reserving(req, &mut |_, _| true).await
    }

    /// [`Self::execute`], asking `reserve` before each part of the answer is buffered (with
    /// its size, `true`); when it says no, the exchange ends with [`FastCgiError::NoRoom`].
    /// What a failed attempt had buffered is given back (`reserve(size, false)`) before the
    /// request is tried again.
    ///
    /// # Errors
    /// As [`Self::execute`], and [`FastCgiError::NoRoom`].
    pub async fn execute_reserving(
        &self,
        req: &FastCgiRequest<'_>,
        reserve: &mut (dyn FnMut(usize, bool) -> bool + Send),
    ) -> Result<Response<Bytes>, FastCgiError> {
        match self.execute_inner(req, reserve, false).await? {
            FastCgiAnswer::Whole(resp) => Ok(resp),
            // Not asked for: `execute_inner` gives an error in its place.
            FastCgiAnswer::Streamed(..) => Err(FastCgiError::Protocol(format!(
                "FastCGI stdout exceeded maximum response size of {} bytes",
                self.max_response_bytes
            ))),
        }
    }

    /// [`Self::execute_reserving`] for a caller that can send an answer on while it is still
    /// being produced. An answer within the buffer limit is read whole, exactly as there. A
    /// larger one is not refused: once the limit is reached (and the request has been handed
    /// over completely), the head and what was buffered are returned with an [`AnswerTail`]
    /// for the rest. From then on the backend's worker is held until the tail has been read
    /// or dropped, and nothing is tried a second time.
    ///
    /// # Errors
    /// As [`Self::execute_reserving`].
    pub async fn execute_streaming(
        &self,
        req: &FastCgiRequest<'_>,
        reserve: &mut (dyn FnMut(usize, bool) -> bool + Send),
    ) -> Result<FastCgiAnswer, FastCgiError> {
        self.execute_inner(req, reserve, true).await
    }

    async fn execute_inner(
        &self,
        req: &FastCgiRequest<'_>,
        reserve: &mut (dyn FnMut(usize, bool) -> bool + Send),
        stream_beyond: bool,
    ) -> Result<FastCgiAnswer, FastCgiError> {
        let script_filename = self.resolve_script_filename(req.script_name)?;
        let params = build_cgi_params(req, &self.document_root, &script_filename);

        tokio::time::timeout(self.timeout, async {
            let mut buffered = 0_usize;
            let mut counting = |bytes: usize, take: bool| {
                let granted = reserve(bytes, take);
                if take && granted {
                    buffered = buffered.saturating_add(bytes);
                }
                granted
            };
            let first = match self
                .send_over_target(&params, req.body, &mut counting, stream_beyond)
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(err) => err,
            };
            // A graceful PHP-FPM reload closes its listening socket and its workers'
            // connections for a moment. The response is buffered, so nothing has reached the
            // client yet. One more attempt on a fresh connection, inside the same time budget:
            // - always when the connection could not be made, for every method: the backend
            //   never saw the request, so nothing can run twice;
            // - only with `replay-safe-methods`, and only for a method without side effects,
            //   when the connection was lost after the request was handed over: the backend
            //   may already have run it.
            let retry = match &first {
                AttemptError::Connect(err) => is_connection_level_error(err),
                AttemptError::Exchange(FastCgiError::Io(err)) => {
                    self.replay_safe_methods
                        && is_retryable_method(req.method)
                        && is_connection_level_error(err)
                }
                AttemptError::Exchange(_) => false,
            };
            if !retry {
                return Err(first.into());
            }
            // Counted in the log so a deployment can see how often this happens and, for a
            // replay, that a request may have run twice.
            match &first {
                AttemptError::Connect(err) => tracing::info!(
                    script = req.script_name,
                    error = %err,
                    "FastCGI connection could not be made; trying once more"
                ),
                AttemptError::Exchange(err) => tracing::info!(
                    script = req.script_name,
                    method = %req.method,
                    error = %err,
                    "FastCGI connection lost after the request was handed over; replaying (replay-safe-methods)"
                ),
            }
            // The first attempt's part of the answer is gone.
            reserve(buffered, false);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            self.send_over_target(&params, req.body, reserve, stream_beyond)
                .await
                .map_err(FastCgiError::from)
        })
        .await
        .map_err(|_| FastCgiError::Timeout)?
    }

    fn resolve_script_filename(&self, script_name: &str) -> Result<String, FastCgiError> {
        if script_name.is_empty() || script_name.contains('\0') || script_name.contains('\\') {
            return Err(FastCgiError::UnsafeScriptPath(script_name.to_owned()));
        }
        let mut joined = self.document_root.clone();
        for seg in script_name.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                return Err(FastCgiError::UnsafeScriptPath(script_name.to_owned()));
            }
            joined.push(seg);
        }
        Ok(joined.to_string_lossy().into_owned())
    }

    async fn send_over_target(
        &self,
        params: &[(String, String)],
        body: &[u8],
        reserve: &mut (dyn FnMut(usize, bool) -> bool + Send),
        stream_beyond: bool,
    ) -> Result<FastCgiAnswer, AttemptError> {
        let limits = ExchangeLimits {
            max_response_bytes: self.max_response_bytes,
            stream_beyond,
            idle: self.timeout,
        };
        match &self.target {
            FastCgiTarget::Tcp { host, port } => {
                let stream = TcpStream::connect((host.as_str(), *port))
                    .await
                    .map_err(AttemptError::Connect)?;
                let _ = stream.set_nodelay(true);
                run_fcgi_exchange(stream, params, body, limits, reserve)
                    .await
                    .map_err(AttemptError::Exchange)
            }
            FastCgiTarget::Unix { path } => {
                #[cfg(unix)]
                {
                    let stream = tokio::net::UnixStream::connect(path)
                        .await
                        .map_err(AttemptError::Connect)?;
                    run_fcgi_exchange(stream, params, body, limits, reserve)
                        .await
                        .map_err(AttemptError::Exchange)
                }
                #[cfg(not(unix))]
                {
                    Err(AttemptError::Exchange(FastCgiError::UnsupportedTransport(
                        path.clone(),
                    )))
                }
            }
        }
    }
}

impl From<AttemptError> for FastCgiError {
    fn from(err: AttemptError) -> Self {
        match err {
            AttemptError::Connect(io) => Self::Io(io),
            AttemptError::Exchange(err) => err,
        }
    }
}

/// Methods that may be sent to the backend a second time.
fn is_retryable_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// The backend connection could not be made or was dropped (as opposed to a protocol error).
fn is_connection_level_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotFound
    )
}

/// The request id of the one request a connection carries.
const REQUEST_ID: u16 = 1;

/// Size of the read and of the write buffer of one exchange with the backend.
const EXCHANGE_BUFFER_BYTES: usize = 32 * 1024;

/// Records with another request id that an answer may contain before it is refused.
const MAX_UNMATCHED_RECORDS: u32 = 64;

/// What bounds one exchange.
#[derive(Clone, Copy)]
struct ExchangeLimits {
    /// How much of the answer is buffered.
    max_response_bytes: usize,
    /// Whether a larger answer is handed on with an [`AnswerTail`] instead of refused.
    stream_beyond: bool,
    /// The longest wait for the next record of a tail.
    idle: Duration,
}

/// How reading the answer ended.
enum ReadEnd {
    /// The backend ended the request: all of the standard output.
    Complete(Vec<u8>),
    /// The buffer limit was reached first.
    Over {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        /// The record that did not fit.
        pending: Vec<u8>,
        unmatched_records: u32,
    },
}

async fn run_fcgi_exchange<S>(
    stream: S,
    params: &[(String, String)],
    body: &[u8],
    limits: ExchangeLimits,
    reserve: &mut (dyn FnMut(usize, bool) -> bool + Send),
) -> Result<FastCgiAnswer, FastCgiError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let too_large = || {
        FastCgiError::Protocol(format!(
            "FastCGI stdout exceeded maximum response size of {} bytes",
            limits.max_response_bytes
        ))
    };
    // Records are small and many (a header, the content and the padding are separate writes
    // and reads): both directions go through a buffer, so that a request without a large body
    // is one write to the backend and an answer is read in few calls. The bytes on the wire
    // are the same; `write_request` flushes when the request is complete.
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = tokio::io::BufReader::with_capacity(EXCHANGE_BUFFER_BYTES, reader);
    let mut writer = tokio::io::BufWriter::with_capacity(EXCHANGE_BUFFER_BYTES, writer);
    let (end, written) = {
        // The request is written while the answer is read: a backend that answers before it
        // has taken all of its input (an early error, a script that never reads its body)
        // would otherwise wait for us to read while we wait for it to read, until the timeout.
        let write = write_request(&mut writer, params, body);
        let read = read_answer(&mut reader, limits.max_response_bytes, reserve);
        tokio::pin!(write, read);
        let mut written: Option<Result<(), FastCgiError>> = None;
        let end = loop {
            tokio::select! {
                result = &mut write, if written.is_none() => written = Some(result),
                answer = &mut read => break answer,
            }
        };
        (end, written)
    };
    match (end, written) {
        // A complete answer stands, whether or not the backend took the whole request.
        (Ok(ReadEnd::Complete(stdout)), _) => {
            parse_cgi_bytes(&Bytes::from(stdout)).map(FastCgiAnswer::Whole)
        }
        // More than the buffer holds, from a backend that has the whole request: the head and
        // the buffered part now, the rest as it comes.
        (
            Ok(ReadEnd::Over {
                stdout,
                stderr,
                pending,
                unmatched_records,
            }),
            Some(Ok(())),
        ) if limits.stream_beyond => {
            let declared = cgi::declared_content_length(&stdout);
            let mut head = parse_cgi_bytes(&Bytes::from(stdout))?;
            if matches!(
                head.status(),
                http::StatusCode::NO_CONTENT | http::StatusCode::NOT_MODIFIED
            ) {
                // No body goes with these: the rest is not read.
                return Ok(FastCgiAnswer::Whole(head));
            }
            // The length set from the buffered part is not the length of the answer. The
            // backend's own is used when it can still be true: not less than what has come.
            head.headers_mut().remove(http::header::CONTENT_LENGTH);
            let remaining = declared
                .and_then(|total| total.checked_sub(head.body().len() as u64))
                .filter(|left| *left >= pending.len() as u64);
            if let (Some(total), Some(_)) = (declared, remaining) {
                head.headers_mut()
                    .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(total));
            }
            Ok(FastCgiAnswer::Streamed(
                head,
                AnswerTail {
                    reader: Box::new(reader),
                    // The request has been flushed: only the half of the connection is kept.
                    _writer: Box::new(writer.into_inner()),
                    pending: (!pending.is_empty()).then(|| Bytes::from(pending)),
                    remaining,
                    idle: limits.idle,
                    stderr,
                    unmatched_records,
                    done: false,
                    failed: false,
                },
            ))
        }
        (Ok(ReadEnd::Over { .. }), _) => Err(too_large()),
        // No answer: the reason the request could not be written says more than the end of
        // the stream that followed it.
        (Err(FastCgiError::Io(_)), Some(Err(write_error))) => Err(write_error),
        (Err(read_error), _) => Err(read_error),
    }
}

async fn write_request<W>(
    writer: &mut W,
    params: &[(String, String)],
    body: &[u8],
) -> Result<(), FastCgiError>
where
    W: AsyncWrite + Unpin,
{
    // 1. FCGI_BEGIN_REQUEST (role = FCGI_RESPONDER, keep_conn = false)
    let begin = encode_begin_request(false);
    write_record(writer, RecordType::BeginRequest, REQUEST_ID, &begin).await?;

    // 2. FCGI_PARAMS (chunked + empty terminator record)
    let encoded_params = encode_params(params);
    write_stream_records(
        writer,
        RecordType::Params,
        REQUEST_ID,
        &encoded_params,
        true,
    )
    .await?;

    // 3. FCGI_STDIN (request body + empty terminator record)
    write_stream_records(writer, RecordType::Stdin, REQUEST_ID, body, true).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads the answer's records until the end-of-request record, or until the standard output
/// is larger than `max_response_bytes`.
async fn read_answer<R>(
    stream: &mut R,
    max_response_bytes: usize,
    reserve: &mut (dyn FnMut(usize, bool) -> bool + Send),
) -> Result<ReadEnd, FastCgiError>
where
    R: AsyncRead + Unpin,
{
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut unmatched_records = 0_u32;

    loop {
        let rec = read_record(stream).await?;
        if rec.request_id != REQUEST_ID {
            unmatched_records = unmatched_records.saturating_add(1);
            if unmatched_records > MAX_UNMATCHED_RECORDS {
                return Err(FastCgiError::Protocol(
                    "FastCGI backend sent excessive records with mismatched request_id".to_owned(),
                ));
            }
            continue;
        }
        match rec.record_type {
            RecordType::Stdout => {
                if stdout_buf.len().saturating_add(rec.content.len()) > max_response_bytes {
                    return Ok(ReadEnd::Over {
                        stdout: stdout_buf,
                        stderr: stderr_buf,
                        pending: rec.content,
                        unmatched_records,
                    });
                }
                if !reserve(rec.content.len(), true) {
                    return Err(FastCgiError::NoRoom);
                }
                stdout_buf.extend_from_slice(&rec.content);
            }
            RecordType::Stderr => keep_stderr(&mut stderr_buf, &rec.content),
            RecordType::EndRequest => {
                end_of_request(&rec.content, &stderr_buf)?;
                break;
            }
            _ => {}
        }
    }

    Ok(ReadEnd::Complete(stdout_buf))
}

/// Keeps what the backend wrote to its standard error, up to 64 KiB, for the log.
fn keep_stderr(kept: &mut Vec<u8>, content: &[u8]) {
    let avail = (64 * 1024_usize).saturating_sub(kept.len());
    let take = content.len().min(avail);
    if let Some(slice) = content.get(..take) {
        kept.extend_from_slice(slice);
    }
}

/// The end-of-request record: logs the standard error and checks the protocol status.
fn end_of_request(content: &[u8], stderr: &[u8]) -> Result<(), FastCgiError> {
    let end = EndRequestBody::decode(content)?;
    if !stderr.is_empty() {
        let clean_stderr: String = String::from_utf8_lossy(stderr)
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        warn!(
            stderr = %clean_stderr,
            app_status = end.app_status,
            "FastCGI backend wrote to stderr"
        );
    }
    if end.protocol_status != 0 {
        return Err(FastCgiError::Protocol(format!(
            "FastCGI backend terminated with protocol_status={}",
            end.protocol_status
        )));
    }
    Ok(())
}

fn build_cgi_params(
    req: &FastCgiRequest<'_>,
    document_root: &std::path::Path,
    script_filename: &str,
) -> Vec<(String, String)> {
    let proto = match req.version {
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    };

    let content_type = req
        .headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Always derive CONTENT_LENGTH authoritatively from the actual buffered FCGI_STDIN length.
    let content_length = req.body.len().to_string();
    let remote_addr = req
        .client_ip
        .map_or_else(|| "127.0.0.1".to_owned(), |ip| ip.to_string());

    let mut params = vec![
        ("GATEWAY_INTERFACE".to_owned(), "CGI/1.1".to_owned()),
        ("SERVER_SOFTWARE".to_owned(), "MiraServe".to_owned()),
        ("REDIRECT_STATUS".to_owned(), "200".to_owned()),
        ("REQUEST_METHOD".to_owned(), req.method.as_str().to_owned()),
        ("SCRIPT_FILENAME".to_owned(), script_filename.to_owned()),
        ("SCRIPT_NAME".to_owned(), req.script_name.to_owned()),
        (
            "DOCUMENT_ROOT".to_owned(),
            document_root.to_string_lossy().into_owned(),
        ),
        ("REQUEST_URI".to_owned(), req.request_uri.to_owned()),
        ("QUERY_STRING".to_owned(), req.query_string.to_owned()),
        ("SERVER_PROTOCOL".to_owned(), proto.to_owned()),
        ("SERVER_NAME".to_owned(), req.server_name.to_owned()),
        ("SERVER_PORT".to_owned(), req.server_port.to_string()),
        ("REMOTE_ADDR".to_owned(), remote_addr),
        ("CONTENT_TYPE".to_owned(), content_type.to_owned()),
        ("CONTENT_LENGTH".to_owned(), content_length),
    ];

    if !req.path_info.is_empty() {
        params.push(("PATH_INFO".to_owned(), req.path_info.to_owned()));
    }
    if let Some(server_addr) = req.server_addr {
        params.push(("SERVER_ADDR".to_owned(), server_addr.to_string()));
    }
    if let Some(remote_port) = req.remote_port {
        params.push(("REMOTE_PORT".to_owned(), remote_port.to_string()));
    }

    if req.is_https {
        params.push(("HTTPS".to_owned(), "on".to_owned()));
        params.push(("REQUEST_SCHEME".to_owned(), "https".to_owned()));
    } else {
        params.push(("REQUEST_SCHEME".to_owned(), "http".to_owned()));
    }

    // Export HTTP_* headers per RFC 3875 §4.1.18:
    // - Skip `Proxy` (HTTPoxy CVE-2016-5385) and framing/meta headers (`content-type`, `content-length`).
    // - Drop header names containing `_` to prevent CGI HTTP_X_FOO vs HTTP_X-FOO header collision smuggling.
    // - Join duplicate header values (`; ` for Cookie per RFC 6265/9114, `, ` for others).
    let mut saw_http_host = false;
    for name in req.headers.keys() {
        let lower = name.as_str();
        if lower == "proxy"
            || lower == "content-type"
            || lower == "content-length"
            || lower.contains('_')
        {
            continue;
        }
        let sep = if lower == "cookie" { "; " } else { ", " };
        let mut joined = String::new();
        let mut any = false;
        for val in req.headers.get_all(name) {
            if let Ok(val_str) = val.to_str() {
                if any {
                    joined.push_str(sep);
                }
                joined.push_str(val_str);
                any = true;
            }
        }
        if any {
            if lower == "host" {
                saw_http_host = true;
            }
            let cgi_name = format!("HTTP_{}", lower.replace('-', "_").to_ascii_uppercase());
            params.push((cgi_name, joined));
        }
    }

    // FCGI-2: HTTP/2 and HTTP/3 carry the host in `:authority` instead of a `Host` header.
    // Always synthesize `HTTP_HOST` from the validated server authority so PHP/WordPress apps
    // receive `$_SERVER['HTTP_HOST']` consistently across HTTP/1.1, HTTP/2, and HTTP/3.
    if !saw_http_host && !req.server_name.is_empty() {
        let is_default_port =
            (req.is_https && req.server_port == 443) || (!req.is_https && req.server_port == 80);
        let host_val = if is_default_port || req.server_name.contains(':') {
            req.server_name.to_owned()
        } else {
            format!("{}:{}", req.server_name, req.server_port)
        };
        params.push(("HTTP_HOST".to_owned(), host_val));
    }

    params
}

#[cfg(test)]
mod exchange_tests {
    use super::{ExchangeLimits, FastCgiAnswer, FastCgiError, run_fcgi_exchange};
    use crate::protocol::{
        EndRequestBody, RecordType, read_record, write_record, write_stream_records,
    };
    use tokio::io::AsyncWriteExt as _;

    fn limits(max_response_bytes: usize, stream_beyond: bool) -> ExchangeLimits {
        ExchangeLimits {
            max_response_bytes,
            stream_beyond,
            idle: std::time::Duration::from_secs(10),
        }
    }

    /// A backend that answers before it reads its input, both larger than the connection
    /// buffers: the exchange completes instead of each side waiting for the other to read
    /// (Cloudflare-skills audit of v0.1.0, claim 8). The answer is counted while it is read.
    #[tokio::test]
    async fn the_answer_is_read_while_the_request_is_written()
    -> Result<(), Box<dyn std::error::Error>> {
        const SIZE: usize = 512 * 1024;
        let (ours, mut backend) = tokio::io::duplex(4096);
        let backend_task = tokio::spawn(async move {
            // Parameters first, as PHP-FPM starts the script after them.
            loop {
                let rec = read_record(&mut backend).await?;
                if rec.record_type == RecordType::Params && rec.content.is_empty() {
                    break;
                }
            }
            let mut answer = b"Content-Type: text/plain\r\n\r\n".to_vec();
            answer.resize(answer.len() + SIZE, b'a');
            write_stream_records(&mut backend, RecordType::Stdout, 1, &answer, true).await?;
            let end = EndRequestBody {
                app_status: 0,
                protocol_status: 0,
            }
            .encode();
            write_record(&mut backend, RecordType::EndRequest, 1, &end).await?;
            backend.flush().await?;
            // Only now the input.
            loop {
                let rec = read_record(&mut backend).await?;
                if rec.record_type == RecordType::Stdin && rec.content.is_empty() {
                    return Ok::<_, FastCgiError>(());
                }
            }
        });
        let body = vec![b'b'; SIZE];
        let mut counted = 0_usize;
        let mut reserve = |bytes: usize, take: bool| {
            if take {
                counted += bytes;
            }
            true
        };
        let exchange = run_fcgi_exchange(ours, &[], &body, limits(4 * SIZE, false), &mut reserve);
        let answer = tokio::time::timeout(std::time::Duration::from_secs(10), exchange).await??;
        let FastCgiAnswer::Whole(answer) = answer else {
            return Err("an answer within the limit is read whole".into());
        };
        assert_eq!(answer.body().len(), SIZE);
        assert!(counted >= SIZE);
        let _ = backend_task.await?;

        // No room for the answer.
        let (ours, mut backend) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ =
                write_stream_records(&mut backend, RecordType::Stdout, 1, b"x: y\r\n\r\nz", true)
                    .await;
            let _ = backend.flush().await;
            std::future::pending::<()>().await;
        });
        let refused =
            run_fcgi_exchange(ours, &[], b"", limits(1024, false), &mut |_, _| false).await;
        assert!(matches!(refused, Err(FastCgiError::NoRoom)));
        Ok(())
    }

    /// A backend that takes the request and then sends `size` bytes after a short head, ending
    /// the request with `protocol_status`.
    fn sending_backend(
        size: usize,
        protocol_status: u8,
        declared: usize,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<(), FastCgiError>>,
    ) {
        let (ours, mut backend) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            loop {
                let rec = read_record(&mut backend).await?;
                if rec.record_type == RecordType::Stdin && rec.content.is_empty() {
                    break;
                }
            }
            let mut answer =
                format!("Content-Type: application/zip\r\nContent-Length: {declared}\r\n\r\n")
                    .into_bytes();
            answer.extend((0..size).map(|i| u8::try_from(i % 251).unwrap_or(0)));
            write_stream_records(&mut backend, RecordType::Stdout, 1, &answer, true).await?;
            let end = EndRequestBody {
                app_status: 0,
                protocol_status,
            }
            .encode();
            write_record(&mut backend, RecordType::EndRequest, 1, &end).await?;
            backend.flush().await?;
            Ok(())
        });
        (ours, task)
    }

    /// An answer larger than the buffer limit: refused as before when streaming was not asked
    /// for; with streaming, the head and the buffered part come first and the rest follows,
    /// every byte once and in order, with no length claimed for it.
    #[tokio::test]
    async fn an_answer_above_the_limit_is_streamed_when_asked()
    -> Result<(), Box<dyn std::error::Error>> {
        const SIZE: usize = 700 * 1024;
        const LIMIT: usize = 200 * 1024;

        let (ours, _task) = sending_backend(SIZE, 0, 5);
        let refused =
            run_fcgi_exchange(ours, &[], b"", limits(LIMIT, false), &mut |_, _| true).await;
        assert!(matches!(refused, Err(FastCgiError::Protocol(_))));

        let (ours, task) = sending_backend(SIZE, 0, 5);
        let mut counted = 0_usize;
        let mut reserve = |bytes: usize, take: bool| {
            if take {
                counted += bytes;
            }
            true
        };
        let answer = run_fcgi_exchange(ours, &[], b"", limits(LIMIT, true), &mut reserve).await?;
        let FastCgiAnswer::Streamed(head, mut tail) = answer else {
            return Err("an answer above the limit is streamed".into());
        };
        assert_eq!(head.status(), http::StatusCode::OK);
        assert_eq!(
            head.headers()
                .get(http::header::CONTENT_TYPE)
                .map(http::HeaderValue::as_bytes),
            Some(&b"application/zip"[..])
        );
        // Neither the backend's length nor the length of the buffered part.
        assert!(head.headers().get(http::header::CONTENT_LENGTH).is_none());
        // Only the buffered part was counted, and it is within the limit.
        assert!(counted <= LIMIT);
        let mut body = head.into_body().to_vec();
        assert!(body.len() <= LIMIT);
        while let Some(part) = tail.next().await? {
            body.extend_from_slice(&part);
        }
        assert_eq!(body.len(), SIZE);
        assert!(
            body.iter()
                .enumerate()
                .all(|(i, byte)| *byte == u8::try_from(i % 251).unwrap_or(0))
        );
        // The end stays the end.
        assert!(tail.next().await?.is_none());
        task.await??;

        // A request the backend did not end properly is an error of the tail, not an end.
        let (ours, _task) = sending_backend(SIZE, 1, 5);
        let answer =
            run_fcgi_exchange(ours, &[], b"", limits(LIMIT, true), &mut |_, _| true).await?;
        let FastCgiAnswer::Streamed(_, mut tail) = answer else {
            return Err("an answer above the limit is streamed".into());
        };
        let ended = loop {
            match tail.next().await {
                Ok(Some(_)) => {}
                other => break other,
            }
        };
        assert!(matches!(ended, Err(FastCgiError::Protocol(_))));

        Ok(())
    }
    /// A backend that declares a large answer, sends the start of it, and only then reads the
    /// rest of a large request before it goes on: reading does not stop while the request is
    /// still being written (neither side would read), and the answer arrives whole.
    #[tokio::test]
    async fn a_large_answer_interleaved_with_a_large_request_arrives_whole()
    -> Result<(), Box<dyn std::error::Error>> {
        const SIZE: usize = 700 * 1024;
        const LIMIT: usize = 200 * 1024;
        const FIRST: usize = 100 * 1024;
        let (ours, mut backend) = tokio::io::duplex(4096);
        let backend_task = tokio::spawn(async move {
            loop {
                let rec = read_record(&mut backend).await?;
                if rec.record_type == RecordType::Params && rec.content.is_empty() {
                    break;
                }
            }
            let mut start = format!("Content-Length: {SIZE}\r\n\r\n").into_bytes();
            start.resize(start.len() + FIRST, b'a');
            write_stream_records(&mut backend, RecordType::Stdout, 1, &start, false).await?;
            backend.flush().await?;
            loop {
                let rec = read_record(&mut backend).await?;
                if rec.record_type == RecordType::Stdin && rec.content.is_empty() {
                    break;
                }
            }
            let rest = vec![b'a'; SIZE - FIRST];
            write_stream_records(&mut backend, RecordType::Stdout, 1, &rest, true).await?;
            let end = EndRequestBody {
                app_status: 0,
                protocol_status: 0,
            }
            .encode();
            write_record(&mut backend, RecordType::EndRequest, 1, &end).await?;
            backend.flush().await?;
            Ok::<_, FastCgiError>(())
        });
        let body = vec![b'b'; 512 * 1024];
        let mut reserve = |_: usize, _: bool| true;
        let exchange = run_fcgi_exchange(ours, &[], &body, limits(LIMIT, true), &mut reserve);
        let answer = tokio::time::timeout(std::time::Duration::from_secs(10), exchange).await??;
        let FastCgiAnswer::Streamed(head, mut tail) = answer else {
            return Err("a declared length above the limit is streamed".into());
        };
        let mut got = head.into_body().len();
        while let Some(part) = tail.next().await? {
            got += part.len();
        }
        assert_eq!(got, SIZE);
        backend_task.await??;
        Ok(())
    }

    /// A backend that sends no more of the body is given up after the idle time, whether it is
    /// silent or keeps writing to its standard error; an answer that has failed stays failed.
    #[tokio::test]
    async fn a_streamed_answer_without_progress_times_out() -> Result<(), Box<dyn std::error::Error>>
    {
        const LIMIT: usize = 200 * 1024;
        // A backend that keeps writing to its standard error but sends no more of the body:
        // the idle time is for the body, and an answer that has failed stays failed.
        let (ours, mut backend) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut answer = b"x: y\r\n\r\n".to_vec();
            answer.resize(answer.len() + 2 * LIMIT, b'z');
            let _ = write_stream_records(&mut backend, RecordType::Stdout, 1, &answer, false).await;
            loop {
                if write_record(&mut backend, RecordType::Stderr, 1, b"PHP Notice: again\n")
                    .await
                    .is_err()
                    || backend.flush().await.is_err()
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
        let mut short = limits(LIMIT, true);
        short.idle = std::time::Duration::from_millis(300);
        let answer = run_fcgi_exchange(ours, &[], b"", short, &mut |_, _| true).await?;
        let FastCgiAnswer::Streamed(_, mut tail) = answer else {
            return Err("an answer above the limit is streamed".into());
        };
        let started = std::time::Instant::now();
        let ended = loop {
            match tail.next().await {
                Ok(Some(_)) => {}
                other => break other,
            }
        };
        assert!(matches!(ended, Err(FastCgiError::Timeout)));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(tail.next().await.is_err());

        // A backend that stops sending: the tail gives up after the idle time.
        let (ours, mut backend) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut answer = b"x: y\r\n\r\n".to_vec();
            answer.resize(answer.len() + 2 * LIMIT, b'z');
            let _ = write_stream_records(&mut backend, RecordType::Stdout, 1, &answer, false).await;
            let _ = backend.flush().await;
            std::future::pending::<()>().await;
        });
        let mut short = limits(LIMIT, true);
        short.idle = std::time::Duration::from_millis(200);
        let answer = run_fcgi_exchange(ours, &[], b"", short, &mut |_, _| true).await?;
        let FastCgiAnswer::Streamed(_, mut tail) = answer else {
            return Err("an answer above the limit is streamed".into());
        };
        let ended = loop {
            match tail.next().await {
                Ok(Some(_)) => {}
                other => break other,
            }
        };
        assert!(matches!(ended, Err(FastCgiError::Timeout)));
        Ok(())
    }

    /// Which length a head declares: one valid value, also when repeated; none when values
    /// differ, when it is not a number, or when the script names the header in `Connection`
    /// (the parser drops such a header, and so must the length taken from it).
    #[test]
    fn the_declared_length_of_a_head() {
        use crate::cgi::declared_content_length as declared;
        assert_eq!(declared(b"Content-Length: 9\r\n\r\nx"), Some(9));
        assert_eq!(
            declared(b"content-length: 9\r\nContent-Length: 9\r\n\r\n"),
            Some(9)
        );
        assert_eq!(
            declared(b"Content-Length: 9\r\nContent-Length: 8\r\n\r\n"),
            None
        );
        assert_eq!(declared(b"Content-Length: +9\r\n\r\n"), None);
        assert_eq!(declared(b"X: y\r\n\r\n"), None);
        assert_eq!(
            declared(b"Content-Length: 9\r\nConnection: close, Content-Length\r\n\r\n"),
            None
        );
        assert_eq!(
            declared(b"connection: content-length\r\nContent-Length: 9\r\n\r\n"),
            None
        );
    }

    /// A length the backend declares is passed on when it can be true, and then holds: the
    /// exact length gives the whole answer; a longer answer is cut at it; a shorter one is an
    /// error, not an end.
    #[tokio::test]
    async fn a_declared_length_of_a_streamed_answer_is_passed_on_and_kept()
    -> Result<(), Box<dyn std::error::Error>> {
        const SIZE: usize = 700 * 1024;
        const LIMIT: usize = 200 * 1024;
        for (declared, arrives) in [
            (SIZE, Some(SIZE)),
            (SIZE - 1000, Some(SIZE - 1000)),
            (SIZE + 1, None),
        ] {
            let (ours, _task) = sending_backend(SIZE, 0, declared);
            let answer =
                run_fcgi_exchange(ours, &[], b"", limits(LIMIT, true), &mut |_, _| true).await?;
            let FastCgiAnswer::Streamed(head, mut tail) = answer else {
                return Err("an answer above the limit is streamed".into());
            };
            assert_eq!(
                head.headers()
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok()),
                Some(declared)
            );
            let mut got = head.into_body().len();
            let ended = loop {
                match tail.next().await {
                    Ok(Some(part)) => got += part.len(),
                    other => break other,
                }
            };
            match arrives {
                Some(length) => {
                    assert!(matches!(ended, Ok(None)));
                    assert_eq!(got, length);
                }
                None => assert!(matches!(ended, Err(FastCgiError::Protocol(_)))),
            }
        }
        Ok(())
    }
}
