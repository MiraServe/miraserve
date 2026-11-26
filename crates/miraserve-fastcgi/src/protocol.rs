//! Pure-Rust FastCGI 1.0 binary record codec (OpenMarket FastCGI Specification).

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::FastCgiError;

/// FastCGI wire protocol version 1.
pub const FCGI_VERSION_1: u8 = 1;

/// Fixed 8-byte FastCGI record header size.
pub const FCGI_HEADER_LEN: usize = 8;

/// Maximum payload per single FastCGI record (`u16::MAX`).
pub const FCGI_MAX_CONTENT_LEN: usize = 65_535;

/// FastCGI responder role (standard HTTP -> PHP-FPM execution).
pub const FCGI_RESPONDER: u16 = 1;

/// FastCGI record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// Starts a new FastCGI request (`FCGI_BEGIN_REQUEST`).
    BeginRequest = 1,
    /// Aborts an in-flight request (`FCGI_ABORT_REQUEST`).
    AbortRequest = 2,
    /// Signals completion of a request (`FCGI_END_REQUEST`).
    EndRequest = 3,
    /// Name-value CGI environment parameters (`FCGI_PARAMS`).
    Params = 4,
    /// Request body stream (`FCGI_STDIN`).
    Stdin = 5,
    /// Response stream (`FCGI_STDOUT`).
    Stdout = 6,
    /// Error log stream (`FCGI_STDERR`).
    Stderr = 7,
    /// Unknown record type for forward compatibility.
    Unknown(u8),
}

impl From<u8> for RecordType {
    fn from(raw: u8) -> Self {
        match raw {
            1 => Self::BeginRequest,
            2 => Self::AbortRequest,
            3 => Self::EndRequest,
            4 => Self::Params,
            5 => Self::Stdin,
            6 => Self::Stdout,
            7 => Self::Stderr,
            other => Self::Unknown(other),
        }
    }
}

impl From<RecordType> for u8 {
    fn from(value: RecordType) -> Self {
        match value {
            RecordType::BeginRequest => 1,
            RecordType::AbortRequest => 2,
            RecordType::EndRequest => 3,
            RecordType::Params => 4,
            RecordType::Stdin => 5,
            RecordType::Stdout => 6,
            RecordType::Stderr => 7,
            RecordType::Unknown(raw) => raw,
        }
    }
}

/// Decoded FastCGI 1.0 protocol record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCgiRecord {
    /// Record type discriminator.
    pub record_type: RecordType,
    /// Multiplexed request identifier (1 for non-multiplexed connections).
    pub request_id: u16,
    /// Unpadded content payload.
    pub content: Vec<u8>,
}

/// Decoded `FCGI_END_REQUEST` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndRequestBody {
    /// Application-level exit status (`0` on normal PHP completion).
    pub app_status: u32,
    /// FastCGI protocol completion status (`0` = `FCGI_REQUEST_COMPLETE`).
    pub protocol_status: u8,
}

impl EndRequestBody {
    /// Parses the 8-byte `FCGI_END_REQUEST` body.
    ///
    /// # Errors
    /// Returns [`FastCgiError::Protocol`] if the payload is shorter than 8 bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FastCgiError> {
        let Some(head) = bytes.get(..8) else {
            return Err(FastCgiError::Protocol(
                "FCGI_END_REQUEST payload shorter than 8 bytes".to_owned(),
            ));
        };
        let app_status = u32::from_be_bytes([
            *head.first().unwrap_or(&0),
            *head.get(1).unwrap_or(&0),
            *head.get(2).unwrap_or(&0),
            *head.get(3).unwrap_or(&0),
        ]);
        let protocol_status = *head.get(4).unwrap_or(&0);
        Ok(Self {
            app_status,
            protocol_status,
        })
    }

    /// Encodes an 8-byte `FCGI_END_REQUEST` payload.
    #[must_use]
    pub fn encode(self) -> [u8; 8] {
        let app = self.app_status.to_be_bytes();
        [
            app[0],
            app[1],
            app[2],
            app[3],
            self.protocol_status,
            0,
            0,
            0,
        ]
    }
}

/// Encodes an 8-byte `FCGI_BEGIN_REQUEST` payload for `FCGI_RESPONDER`.
#[must_use]
pub fn encode_begin_request(keep_conn: bool) -> [u8; 8] {
    let role = FCGI_RESPONDER.to_be_bytes();
    let flags = u8::from(keep_conn);
    [role[0], role[1], flags, 0, 0, 0, 0, 0]
}

/// Encodes CGI name-value parameter pairs in FastCGI 1.0 variable-length binary format.
#[must_use]
pub fn encode_params(params: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(params.len().saturating_mul(32));
    for (name, value) in params {
        write_nv_len(&mut out, name.len());
        write_nv_len(&mut out, value.len());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Decodes FastCGI 1.0 binary name-value parameter bytes into `(name, value)` pairs.
///
/// # Errors
/// Returns [`FastCgiError::Protocol`] if lengths truncate past the buffer end.
pub fn decode_params(bytes: &[u8]) -> Result<Vec<(String, String)>, FastCgiError> {
    let mut out = Vec::new();
    let mut pos = 0_usize;
    while pos < bytes.len() {
        let (name_len, after_name_len) = read_nv_len(bytes, pos)?;
        let (val_len, after_val_len) = read_nv_len(bytes, after_name_len)?;
        let name_end = after_val_len.saturating_add(name_len);
        let val_end = name_end.saturating_add(val_len);
        let Some(name_slice) = bytes.get(after_val_len..name_end) else {
            return Err(FastCgiError::Protocol(
                "truncated FCGI_PARAMS name".to_owned(),
            ));
        };
        let Some(val_slice) = bytes.get(name_end..val_end) else {
            return Err(FastCgiError::Protocol(
                "truncated FCGI_PARAMS value".to_owned(),
            ));
        };
        out.push((
            String::from_utf8_lossy(name_slice).into_owned(),
            String::from_utf8_lossy(val_slice).into_owned(),
        ));
        pos = val_end;
    }
    Ok(out)
}

fn write_nv_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let len32 = u32::try_from(len).unwrap_or(0x7FFF_FFFF) & 0x7FFF_FFFF;
        let encoded = len32 | 0x8000_0000;
        out.extend_from_slice(&encoded.to_be_bytes());
    }
}

fn read_nv_len(bytes: &[u8], pos: usize) -> Result<(usize, usize), FastCgiError> {
    let first = *bytes
        .get(pos)
        .ok_or_else(|| FastCgiError::Protocol("unexpected EOF reading FCGI length".to_owned()))?;
    if first & 0x80 == 0 {
        Ok((usize::from(first), pos.saturating_add(1)))
    } else {
        let b0 = first & 0x7F;
        let b1 = *bytes
            .get(pos.saturating_add(1))
            .ok_or_else(|| FastCgiError::Protocol("truncated 4-byte FCGI length".to_owned()))?;
        let b2 = *bytes
            .get(pos.saturating_add(2))
            .ok_or_else(|| FastCgiError::Protocol("truncated 4-byte FCGI length".to_owned()))?;
        let b3 = *bytes
            .get(pos.saturating_add(3))
            .ok_or_else(|| FastCgiError::Protocol("truncated 4-byte FCGI length".to_owned()))?;
        let len = u32::from_be_bytes([b0, b1, b2, b3]);
        Ok((
            usize::try_from(len).unwrap_or(usize::MAX),
            pos.saturating_add(4),
        ))
    }
}

/// Writes a potentially large payload as one or more 8-byte-aligned FastCGI records,
/// always followed by a zero-length terminating stream record when `terminate_stream` is `true`.
///
/// # Errors
/// Returns [`FastCgiError::Io`] on transport write failures.
pub async fn write_stream_records<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record_type: RecordType,
    request_id: u16,
    payload: &[u8],
    terminate_stream: bool,
) -> Result<(), FastCgiError> {
    for chunk in payload.chunks(FCGI_MAX_CONTENT_LEN) {
        write_record(writer, record_type, request_id, chunk).await?;
    }
    if terminate_stream {
        write_record(writer, record_type, request_id, &[]).await?;
    }
    Ok(())
}

/// Writes a single FastCGI record (content length must be `<= 65535`).
///
/// # Errors
/// Returns [`FastCgiError`] if the payload exceeds 65,535 bytes or transport write fails.
pub async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record_type: RecordType,
    request_id: u16,
    content: &[u8],
) -> Result<(), FastCgiError> {
    let content_len = u16::try_from(content.len()).map_err(|_| {
        FastCgiError::Protocol("single FastCGI record exceeds 65535 bytes".to_owned())
    })?;
    let padding_len = u8::try_from((8 - (content.len() % 8)) % 8).unwrap_or(0);
    let req_bytes = request_id.to_be_bytes();
    let len_bytes = content_len.to_be_bytes();

    let header = [
        FCGI_VERSION_1,
        u8::from(record_type),
        req_bytes[0],
        req_bytes[1],
        len_bytes[0],
        len_bytes[1],
        padding_len,
        0,
    ];

    writer.write_all(&header).await?;
    if !content.is_empty() {
        writer.write_all(content).await?;
    }
    if padding_len > 0 {
        let pad = [0_u8; 8];
        if let Some(pad_slice) = pad.get(..usize::from(padding_len)) {
            writer.write_all(pad_slice).await?;
        }
    }
    Ok(())
}

/// Decodes an 8-byte FastCGI 1.0 record header into `(record_type, request_id, content_len, padding_len)`.
///
/// # Errors
/// Returns [`FastCgiError::Protocol`] if the FastCGI protocol version byte is not `1`.
pub fn decode_record_header(
    header: [u8; FCGI_HEADER_LEN],
) -> Result<(RecordType, u16, u16, u8), FastCgiError> {
    if header[0] != FCGI_VERSION_1 {
        return Err(FastCgiError::Protocol(format!(
            "unsupported FastCGI version {}",
            header[0]
        )));
    }
    let record_type = RecordType::from(header[1]);
    let request_id = u16::from_be_bytes([header[2], header[3]]);
    let content_len = u16::from_be_bytes([header[4], header[5]]);
    let padding_len = header[6];
    Ok((record_type, request_id, content_len, padding_len))
}

/// Reads and decodes a single FastCGI record from an async stream.
///
/// # Errors
/// Returns [`FastCgiError`] on EOF, unsupported version, or transport I/O errors.
pub async fn read_record<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<FastCgiRecord, FastCgiError> {
    let mut header = [0_u8; FCGI_HEADER_LEN];
    reader.read_exact(&mut header).await?;

    let (record_type, request_id, content_len_u16, padding_len_u8) = decode_record_header(header)?;
    let content_len = usize::from(content_len_u16);
    let padding_len = usize::from(padding_len_u8);

    let mut content = vec![0_u8; content_len];
    if content_len > 0 {
        reader.read_exact(&mut content).await?;
    }
    if padding_len > 0 {
        let mut discard = vec![0_u8; padding_len];
        reader.read_exact(&mut discard).await?;
    }

    Ok(FastCgiRecord {
        record_type,
        request_id,
        content,
    })
}
