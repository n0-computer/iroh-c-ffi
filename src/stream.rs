use std::time::Duration;

use safer_ffi::{prelude::*, slice, vec};

use crate::endpoint::EndpointResult;
use crate::util::TOKIO_EXECUTOR;

/// A stream that can only be used to receive data.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Default)]
pub struct RecvStream {
    pub(crate) stream: Option<iroh::endpoint::RecvStream>,
}

/// Must be freed using `recv_stream_free`.
#[ffi_export]
pub fn recv_stream_default() -> repr_c::Box<RecvStream> {
    Box::<RecvStream>::default().into()
}

/// Free the recv stream.
///
/// Implicitly calls `stop(0)` on the connection.
///
/// Must be called before `endpoint_free`
#[ffi_export]
pub fn recv_stream_free(stream: repr_c::Box<RecvStream>) {
    drop(stream);
}

/// Unique stream id.
#[ffi_export]
pub fn recv_stream_id(stream: &repr_c::Box<RecvStream>) -> u64 {
    stream
        .stream
        .as_ref()
        .expect("recvstream not initialized")
        .id()
        .index()
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

/// Receive data on this stream and return with an error if reading exceeds the
/// given timeout.
///
/// Blocks the current thread.
///
/// On success, returns how many bytes were read in the `bytes_read` parameter.
#[ffi_export]
pub fn recv_stream_read_timeout(
    stream: &mut repr_c::Box<RecvStream>,
    mut data: slice::slice_mut<'_, u8>,
    // bytes_read: &mut u64,
    timeout_ms: u64,
    // ) -> EndpointResult {
) -> i64 {
    let timeout = Duration::from_millis(timeout_ms);

    let res = TOKIO_EXECUTOR.block_on(async move {
        tokio::time::timeout(timeout, async move {
            stream
                .stream
                .as_mut()
                .expect("sendstream not initialized")
                .read(&mut data)
                .await
        })
        .await
    });

    match res {
        Ok(Ok(read)) => {
            read.unwrap_or(0) as i64
            // *bytes_read = read.unwrap_or(0) as i64
            // EndpointResult::Ok
        }
        Ok(Err(_err)) => {
            // EndpointResult::ReadError,
            -1
        }
        Err(_err) => {
            // EndpointResult::Timeout,
            -2
        }
    }
}

/// Receive data on this stream.
///
/// Size limit specifies how much data at most is read.
///
/// Blocks the current thread, until either the full stream has been read, or
/// the timeout has expired.
#[ffi_export]
pub fn recv_stream_read_to_end_timeout(
    stream: &mut repr_c::Box<RecvStream>,
    data: &mut vec::Vec<u8>,
    size_limit: usize,
    timeout_ms: u64,
) -> EndpointResult {
    let timeout = Duration::from_millis(timeout_ms);
    let res = TOKIO_EXECUTOR.block_on(async move {
        tokio::time::timeout(timeout, async move {
            stream
                .stream
                .as_mut()
                .expect("sendstream not initialized")
                .read_to_end(size_limit)
                .await
        })
        .await
    });

    match res {
        Ok(Ok(read)) => {
            data.with_rust_mut(|v| {
                *v = read;
            });
            EndpointResult::Ok
        }
        Ok(Err(_err)) => EndpointResult::ReadError,
        Err(_err) => EndpointResult::Timeout,
    }
}

/// A stream that can only be used to send data
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Default)]
pub struct SendStream {
    pub(crate) stream: Option<iroh::endpoint::SendStream>,
}

/// Must be freed using `send_stream_free`.
#[ffi_export]
pub fn send_stream_default() -> repr_c::Box<SendStream> {
    Box::<SendStream>::default().into()
}

/// Frees the send stream.
///
/// Must be called before `endpoint_free`
#[ffi_export]
pub fn send_stream_free(stream: repr_c::Box<SendStream>) {
    drop(stream);
}

/// Unique stream id.
#[ffi_export]
pub fn send_stream_id(stream: &repr_c::Box<SendStream>) -> u64 {
    stream
        .stream
        .as_ref()
        .expect("sendstream not initialized")
        .id()
        .index()
}

/// Send data on the stream.
///
/// Blocks the current thread.
#[ffi_export]
pub fn send_stream_write(
    stream: &mut repr_c::Box<SendStream>,
    data: slice::slice_ref<'_, u8>,
) -> EndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        stream
            .stream
            .as_mut()
            .expect("sendstream not initialized")
            .write_all(&data)
            .await
    });

    match res {
        Ok(()) => EndpointResult::Ok,
        Err(_err) => EndpointResult::SendError,
    }
}

/// Send data on the stream, returning an error if the data was not written
/// before the given timeout.
///
/// Blocks the current thread.
#[ffi_export]
pub fn send_stream_write_timeout(
    stream: &mut repr_c::Box<SendStream>,
    data: slice::slice_ref<'_, u8>,
    timeout_ms: u64,
) -> EndpointResult {
    let timeout = Duration::from_millis(timeout_ms);
    let res = TOKIO_EXECUTOR.block_on(async move {
        tokio::time::timeout(timeout, async move {
            stream
                .stream
                .as_mut()
                .expect("sendstream not initialized")
                .write_all(&data)
                .await
        })
        .await
    });

    match res {
        Ok(Ok(())) => EndpointResult::Ok,
        Ok(Err(_err)) => EndpointResult::SendError,
        Err(_err) => EndpointResult::Timeout,
    }
}

/// Finish the sending on this stream.
///
/// Consumes the send stream, no need to free it afterwards.
#[ffi_export]
pub fn send_stream_finish(mut stream: repr_c::Box<SendStream>) -> EndpointResult {
    let res = stream
        .stream
        .as_mut()
        .expect("sendstream not initialized")
        .finish();

    match res {
        Ok(()) => EndpointResult::Ok,
        Err(_err) => {
            dbg!(_err);
            EndpointResult::SendError
        }
    }
}
