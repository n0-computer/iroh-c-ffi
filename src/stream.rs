use safer_ffi::{prelude::*, slice};

use crate::magic_endpoint::MagicEndpointResult;
use crate::util::TOKIO_EXECUTOR;

/// A stream that can only be used to receive data.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Default)]
pub struct RecvStream {
    pub(crate) stream: Option<quinn::RecvStream>,
}

/// Must be freed using `recv_stream_free`.
#[ffi_export]
pub fn recv_stream_default() -> repr_c::Box<RecvStream> {
    Box::<RecvStream>::default().into()
}

/// Free the recv stream.
///
/// Implicitly calls `stop(0)` on the connection.
#[ffi_export]
pub fn recv_stream_free(stream: repr_c::Box<RecvStream>) {
    drop(stream);
}

/// Receive data on this stream.
///
/// Blocks the current thread.
///
/// Returns how many bytes were read. Returns `-1` if an error occured.
#[ffi_export]
pub fn recv_stream_read(
    stream: &mut repr_c::Box<RecvStream>,
    mut data: slice::slice_mut<'_, u8>,
) -> i64 {
    let res = TOKIO_EXECUTOR.block_on(async move {
        stream
            .stream
            .as_mut()
            .expect("sendstream not initialized")
            .read(&mut data)
            .await
    });

    match res {
        Ok(read) => read.unwrap_or(0) as i64,
        Err(_err) => -1,
    }
}

/// A stream that can only be used to send data
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Default)]
pub struct SendStream {
    pub(crate) stream: Option<quinn::SendStream>,
}

/// Must be freed using `send_stream_free`.
#[ffi_export]
pub fn send_stream_default() -> repr_c::Box<SendStream> {
    Box::<SendStream>::default().into()
}

/// Frees the send stream.
#[ffi_export]
pub fn send_stream_free(stream: repr_c::Box<SendStream>) {
    drop(stream);
}

/// Send data on the stream.
///
/// Blocks the current thread.
#[ffi_export]
pub fn send_stream_write(
    stream: &mut repr_c::Box<SendStream>,
    data: slice::slice_ref<'_, u8>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        stream
            .stream
            .as_mut()
            .expect("sendstream not initialized")
            .write_all(&data)
            .await
    });

    match res {
        Ok(()) => MagicEndpointResult::Ok,
        Err(_err) => MagicEndpointResult::SendError,
    }
}

/// Finish the sending on this stream.
///
/// Consumes the send stream, no need to free it afterwards.
///
/// Blocks the current thread.
#[ffi_export]
pub fn send_stream_finish(mut stream: repr_c::Box<SendStream>) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        stream
            .stream
            .as_mut()
            .expect("sendstream not initialized")
            .finish()
            .await
    });

    match res {
        Ok(()) => MagicEndpointResult::Ok,
        Err(_err) => MagicEndpointResult::SendError,
    }
}