//! QUIC transport for the HTTP/3 library, on Quinn.
//!
//! This is the `h3-quinn` crate (version 0.0.10, MIT, copyright (c) 2020 h3 authors; licence
//! text below) with two changes to its send stream, which MiraServe needs and the crate does
//! not offer:
//!
//! - Ending a request's stream (`poll_finish`) waits until the peer has acknowledged all of it, and
//!   fails if the peer stopped the stream instead. Upstream returns as soon as the end is
//!   queued, and Quinn reports a stream the peer has stopped as ended successfully.
//! - A write that waits (for credit of the stream or of the connection) fails when the peer
//!   has stopped the stream. Quinn does not report the stop while the connection has no
//!   credit.
//!
//! So a request's task knows when its answer has been delivered, and a cancellation by the
//! peer is always seen. [`Shared`] tells the server two things about the connection's streams
//! (whether a stream's end is queued; how many stop notifications Quinn still holds for
//! streams that were reset here). Everything else is upstream's code.
//!
//! Copyright (c) 2020 h3 authors
//!
//! Permission is hereby granted, free of charge, to any
//! person obtaining a copy of this software and associated
//! documentation files (the "Software"), to deal in the
//! Software without restriction, including without
//! limitation the rights to use, copy, modify, merge,
//! publish, distribute, sublicense, and/or sell copies of
//! the Software, and to permit persons to whom the Software
//! is furnished to do so, subject to the following
//! conditions:
//!
//! The above copyright notice and this permission notice
//! shall be included in all copies or substantial portions
//! of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
//! ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
//! TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
//! PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
//! SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//! CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//! OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
//! IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//! DEALINGS IN THE SOFTWARE.

// Upstream's code is kept as it is, with its own conventions (its `expect`s on streams that
// never end and on stream identifiers are upstream's too).
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unreachable,
    missing_docs,
    unreachable_pub,
    dead_code
)]

use std::{
    convert::TryInto,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use bytes::{Buf, Bytes};

use futures_util::{
    Stream, StreamExt, ready,
    stream::{self},
};

use quinn::ReadError;
use quinn::{AcceptBi, AcceptUni, OpenBi, OpenUni, VarInt};

use h3::{
    error::Code,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};
use tokio_util::sync::ReusableBoxFuture;

/// BoxStream with Sync trait
type BoxStreamSync<'a, T> = Pin<Box<dyn Stream<Item = T> + Sync + Send + 'a>>;

/// A QUIC connection backed by Quinn
///
/// Implements a [`quic::Connection`] backed by a [`quinn::Connection`].
pub struct Connection {
    conn: quinn::Connection,
    shared: Arc<Shared>,
    incoming_bi: BoxStreamSync<'static, <AcceptBi<'static> as Future>::Output>,
    opening_bi: Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    incoming_uni: BoxStreamSync<'static, <AcceptUni<'static> as Future>::Output>,
    opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
}

/// What the server may ask about a connection's send streams.
#[derive(Debug, Default)]
pub struct Shared {
    /// Streams whose end is queued and that still exist here.
    fin_queued: std::sync::Mutex<std::collections::HashSet<u64>>,
    /// Streams reset here while Quinn held a stop notification for them. Quinn drops such a
    /// notification only when the stream ends or is stopped by the peer, so after a reset of
    /// ours it stays until the connection closes: the server counts them and replaces a
    /// connection that has gathered too many.
    stale_notifications: std::sync::atomic::AtomicU32,
}

impl Shared {
    /// Whether the end of the stream is queued (what remains is the peer's acknowledgement).
    pub fn fin_queued(&self, stream: u64) -> bool {
        self.fin_queued
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&stream)
    }

    /// See the field.
    pub fn stale_notifications(&self) -> u32 {
        self.stale_notifications
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

impl Connection {
    /// What the server may ask about this connection's streams.
    pub fn shared(&self) -> Arc<Shared> {
        Arc::clone(&self.shared)
    }

    /// Create a [`Connection`] from a [`quinn::Connection`]
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            conn: conn.clone(),
            shared: Arc::new(Shared::default()),
            incoming_bi: Box::pin(stream::unfold(conn.clone(), |conn| async {
                Some((conn.accept_bi().await, conn))
            })),
            opening_bi: None,
            incoming_uni: Box::pin(stream::unfold(conn.clone(), |conn| async {
                Some((conn.accept_uni().await, conn))
            })),
            opening_uni: None,
        }
    }
}

impl<B> quic::Connection<B> for Connection
where
    B: Buf,
{
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;
    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let (send, recv) = ready!(self.incoming_bi.poll_next_unpin(cx))
            .expect("self.incoming_bi BoxStream never returns None")
            .map_err(|e| convert_connection_error(e))?;
        Poll::Ready(Ok(Self::BidiStream {
            send: Self::SendStream::new(send, &self.shared),
            recv: Self::RecvStream::new(recv),
        }))
    }
    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        let recv = ready!(self.incoming_uni.poll_next_unpin(cx))
            .expect("self.incoming_uni BoxStream never returns None")
            .map_err(|e| convert_connection_error(e))?;
        Poll::Ready(Ok(Self::RecvStream::new(recv)))
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams {
            conn: self.conn.clone(),
            shared: Arc::clone(&self.shared),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

fn convert_connection_error(e: quinn::ConnectionError) -> h3::quic::ConnectionErrorIncoming {
    match e {
        quinn::ConnectionError::ApplicationClosed(application_close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: application_close.error_code.into(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,

        error @ quinn::ConnectionError::VersionMismatch
        | error @ quinn::ConnectionError::Reset
        | error @ quinn::ConnectionError::LocallyClosed
        | error @ quinn::ConnectionError::CidsExhausted
        | error @ quinn::ConnectionError::TransportError(_)
        | error @ quinn::ConnectionError::ConnectionClosed(_) => {
            ConnectionErrorIncoming::Undefined(Arc::new(error))
        }
    }
}

impl<B> quic::OpenStreams<B> for Connection
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let bi = self.opening_bi.get_or_insert_with(|| {
            Box::pin(stream::unfold(self.conn.clone(), |conn| async {
                Some((conn.open_bi().await, conn))
            }))
        });
        let (send, recv) = ready!(bi.poll_next_unpin(cx))
            .expect("BoxStream does not return None")
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })?;
        Poll::Ready(Ok(Self::BidiStream {
            send: Self::SendStream::new(send, &self.shared),
            recv: RecvStream::new(recv),
        }))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let uni = self.opening_uni.get_or_insert_with(|| {
            Box::pin(stream::unfold(self.conn.clone(), |conn| async {
                Some((conn.open_uni().await, conn))
            }))
        });

        let send = ready!(uni.poll_next_unpin(cx))
            .expect("BoxStream does not return None")
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })?;
        Poll::Ready(Ok(Self::SendStream::new(send, &self.shared).one_way()))
    }
    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            VarInt::from_u64(code.value()).expect("error code VarInt"),
            reason,
        );
    }
}

/// Stream opener backed by a Quinn connection
///
/// Implements [`quic::OpenStreams`] using [`quinn::Connection`],
/// [`quinn::OpenBi`], [`quinn::OpenUni`].
pub struct OpenStreams {
    conn: quinn::Connection,
    shared: Arc<Shared>,
    opening_bi: Option<BoxStreamSync<'static, <OpenBi<'static> as Future>::Output>>,
    opening_uni: Option<BoxStreamSync<'static, <OpenUni<'static> as Future>::Output>>,
}

impl<B> quic::OpenStreams<B> for OpenStreams
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;
    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let bi = self.opening_bi.get_or_insert_with(|| {
            Box::pin(stream::unfold(self.conn.clone(), |conn| async {
                Some((conn.open_bi().await, conn))
            }))
        });

        let (send, recv) = ready!(bi.poll_next_unpin(cx))
            .expect("BoxStream does not return None")
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })?;
        Poll::Ready(Ok(Self::BidiStream {
            send: Self::SendStream::new(send, &self.shared),
            recv: RecvStream::new(recv),
        }))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let uni = self.opening_uni.get_or_insert_with(|| {
            Box::pin(stream::unfold(self.conn.clone(), |conn| async {
                Some((conn.open_uni().await, conn))
            }))
        });

        let send = ready!(uni.poll_next_unpin(cx))
            .expect("BoxStream does not return None")
            .map_err(|e| StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(e),
            })?;
        Poll::Ready(Ok(Self::SendStream::new(send, &self.shared).one_way()))
    }
    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            VarInt::from_u64(code.value()).expect("error code VarInt"),
            reason,
        );
    }
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            shared: Arc::clone(&self.shared),
            opening_bi: None,
            opening_uni: None,
        }
    }
}

/// Quinn-backed bidirectional stream
///
/// Implements [`quic::BidiStream`] which allows the stream to be split
/// into two structs each implementing one direction.
pub struct BidiStream<B>
where
    B: Buf,
{
    send: SendStream<B>,
    recv: RecvStream,
}

impl<B> quic::BidiStream<B> for BidiStream<B>
where
    B: Buf,
{
    type SendStream = SendStream<B>;
    type RecvStream = RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B> quic::SendStream<B> for BidiStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}
impl<B> quic::SendStreamUnframed<B> for BidiStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.send.poll_send(cx, buf)
    }
}

/// Quinn-backed receive stream
///
/// Implements a [`quic::RecvStream`] backed by a [`quinn::RecvStream`].
pub struct RecvStream {
    stream: Option<quinn::RecvStream>,
    read_chunk_fut: ReadChunkFuture,
}

type ReadChunkFuture = ReusableBoxFuture<
    'static,
    (
        quinn::RecvStream,
        Result<Option<quinn::Chunk>, quinn::ReadError>,
    ),
>;

impl RecvStream {
    fn new(stream: quinn::RecvStream) -> Self {
        Self {
            stream: Some(stream),
            // Should only allocate once the first time it's used
            read_chunk_fut: ReusableBoxFuture::new(async { unreachable!() }),
        }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        if let Some(mut stream) = self.stream.take() {
            self.read_chunk_fut.set(async move {
                let chunk = stream.read_chunk(usize::MAX, true).await;
                (stream, chunk)
            })
        };

        let (stream, chunk) = ready!(self.read_chunk_fut.poll(cx));
        self.stream = Some(stream);
        Poll::Ready(Ok(chunk
            .map_err(|e| convert_read_error_to_stream_error(e))?
            .map(|c| c.bytes)))
    }
    fn stop_sending(&mut self, error_code: u64) {
        self.stream
            .as_mut()
            .unwrap()
            .stop(VarInt::from_u64(error_code).expect("invalid error_code"))
            .ok();
    }
    fn recv_id(&self) -> StreamId {
        let num: u64 = self.stream.as_ref().unwrap().id().into();

        num.try_into().expect("invalid stream id")
    }
}

fn convert_read_error_to_stream_error(error: ReadError) -> StreamErrorIncoming {
    match error {
        ReadError::Reset(var_int) => StreamErrorIncoming::StreamTerminated {
            error_code: var_int.into_inner(),
        },
        ReadError::ConnectionLost(connection_error) => {
            StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(connection_error),
            }
        }
        error @ ReadError::ClosedStream => StreamErrorIncoming::Unknown(Box::new(error)),
        ReadError::IllegalOrderedRead => panic!("h3-quinn only performs ordered reads"),
        error @ ReadError::ZeroRttRejected => StreamErrorIncoming::Unknown(Box::new(error)),
    }
}

fn convert_write_error_to_stream_error(error: quinn::WriteError) -> StreamErrorIncoming {
    match error {
        quinn::WriteError::Stopped(var_int) => StreamErrorIncoming::StreamTerminated {
            error_code: var_int.into_inner(),
        },
        quinn::WriteError::ConnectionLost(connection_error) => {
            StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: convert_connection_error(connection_error),
            }
        }
        error @ quinn::WriteError::ClosedStream | error @ quinn::WriteError::ZeroRttRejected => {
            StreamErrorIncoming::Unknown(Box::new(error))
        }
    }
}

/// Quinn-backed send stream
///
/// Implements a [`quic::SendStream`] backed by a [`quinn::SendStream`].
pub struct SendStream<B: Buf> {
    stream: quinn::SendStream,
    writing: Option<WriteBuf<B>>,
    /// Resolves when the peer has stopped the stream or acknowledged all of it; made when
    /// first needed.
    stopped: Option<Stopped>,
    /// The end has been queued.
    finished: bool,
    shared: Arc<Shared>,
    /// A stream of a request: its end waits for the peer's acknowledgement. The library's own
    /// one-way streams end as upstream's do (it ends one while it reads the control stream,
    /// and must not wait there).
    awaits_delivery: bool,
}

impl<B: Buf> Drop for SendStream<B> {
    fn drop(&mut self) {
        if self.finished {
            let id: u64 = self.stream.id().into();
            self.shared
                .fin_queued
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
        }
    }
}

type Stopped =
    Pin<Box<dyn Future<Output = Result<Option<VarInt>, quinn::StoppedError>> + Send + Sync>>;

impl<B> SendStream<B>
where
    B: Buf,
{
    fn new(stream: quinn::SendStream, shared: &Arc<Shared>) -> SendStream<B> {
        Self {
            stream,
            writing: None,
            stopped: None,
            finished: false,
            shared: Arc::clone(shared),
            awaits_delivery: true,
        }
    }

    fn one_way(mut self) -> Self {
        self.awaits_delivery = false;
        self
    }

    /// Whether the peer has stopped the stream (`Some(code)`) or acknowledged all of it after
    /// its end was queued (`None`).
    fn poll_stopped(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<VarInt>, quinn::StoppedError>> {
        let stream = &self.stream;
        self.stopped
            .get_or_insert_with(|| Box::pin(stream.stopped()))
            .as_mut()
            .poll(cx)
    }

    /// A write is waiting: fails if the peer has stopped the stream meanwhile.
    fn stopped_while_waiting(&mut self, cx: &mut task::Context<'_>) -> Option<StreamErrorIncoming> {
        match self.poll_stopped(cx) {
            Poll::Ready(Ok(Some(code))) => Some(StreamErrorIncoming::StreamTerminated {
                error_code: code.into_inner(),
            }),
            // Answered before it was asked: ask anew the next time.
            Poll::Ready(_) => {
                self.stopped = None;
                None
            }
            Poll::Pending => None,
        }
    }
}

impl<B> quic::SendStream<B> for SendStream<B>
where
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        while let Some(data) = self.writing.as_mut() {
            if !data.has_remaining() {
                break;
            }
            let stream = Pin::new(&mut self.stream);
            match stream.poll_write(cx, data.chunk()) {
                Poll::Ready(Ok(written)) => data.advance(written),
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(convert_write_error_to_stream_error(err)));
                }
                Poll::Pending => {
                    return match self.stopped_while_waiting(cx) {
                        Some(err) => Poll::Ready(Err(err)),
                        None => Poll::Pending,
                    };
                }
            }
        }
        // all data is written
        self.writing = None;
        Poll::Ready(Ok(()))
    }
    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if !self.awaits_delivery {
            return Poll::Ready(
                self.stream
                    .finish()
                    .map_err(|e| StreamErrorIncoming::Unknown(Box::new(e))),
            );
        }
        if !self.finished {
            if let Err(e) = self.stream.finish() {
                return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(e))));
            }
            self.finished = true;
            let id: u64 = self.stream.id().into();
            self.shared
                .fin_queued
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(id);
            // Asked anew: an answer from before the end was queued says nothing about it.
            self.stopped = None;
        }
        let outcome = ready!(self.poll_stopped(cx));
        // Answered: Quinn holds no notification for this stream any more.
        self.stopped = None;
        Poll::Ready(match outcome {
            Ok(None) => Ok(()),
            Ok(Some(code)) => Err(StreamErrorIncoming::StreamTerminated {
                error_code: code.into_inner(),
            }),
            Err(quinn::StoppedError::ConnectionLost(e)) => {
                Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: convert_connection_error(e),
                })
            }
            Err(e @ quinn::StoppedError::ZeroRttRejected) => {
                Err(StreamErrorIncoming::Unknown(Box::new(e)))
            }
        })
    }
    fn reset(&mut self, reset_code: u64) {
        // A question about this stream is still open: its notification stays with Quinn.
        if self.stopped.take().is_some() {
            self.shared
                .stale_notifications
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        let _ = self
            .stream
            .reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::MAX));
    }
    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            // This can only happen if the traits are misused by h3 itself
            // If this happens log an error and close the connection with H3_INTERNAL_ERROR
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "internal error in the http stack".to_string(),
                ),
            });
        }
        self.writing = Some(data.into());
        Ok(())
    }
    fn send_id(&self) -> StreamId {
        let num: u64 = self.stream.id().into();
        num.try_into().expect("invalid stream id")
    }
}

impl<B> quic::SendStreamUnframed<B> for SendStream<B>
where
    B: Buf,
{
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        if self.writing.is_some() {
            // This signifies a bug in implementation
            panic!("poll_send called while send stream is not ready")
        }

        let s = Pin::new(&mut self.stream);

        match s.poll_write(cx, buf.chunk()) {
            Poll::Ready(Ok(written)) => {
                buf.advance(written);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(convert_write_error_to_stream_error(err))),
            Poll::Pending => match self.stopped_while_waiting(cx) {
                Some(err) => Poll::Ready(Err(err)),
                None => Poll::Pending,
            },
        }
    }
}
