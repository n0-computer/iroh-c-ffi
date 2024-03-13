use once_cell::sync::Lazy;
use safer_ffi::{prelude::*, vec};
use tracing_subscriber::{prelude::*, EnvFilter};

pub(crate) static TOKIO_EXECUTOR: Lazy<tokio::runtime::Runtime> =
    Lazy::new(|| tokio::runtime::Runtime::new().unwrap());

/// Frees a Rust-allocated string.
#[ffi_export]
pub fn rust_free_string(string: char_p::Box) {
    drop(string)
}

/// Allocates a buffer managed by rust, given the initial size.
#[ffi_export]
pub fn rust_buffer_alloc(size: usize) -> vec::Vec<u8> {
    vec![0u8; size].into()
}

/// Returns the length of the buffer.
#[ffi_export]
pub fn rust_buffer_len(buf: &vec::Vec<u8>) -> usize {
    buf.len()
}

/// Frees the rust buffer.
#[ffi_export]
pub fn rust_buffer_free(buf: vec::Vec<u8>) {
    drop(buf);
}

/// Enables tracing for iroh.
///
/// Log level can be controlled using the env variable `IROH_NET_LOG`.
#[ffi_export]
pub fn iroh_enable_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .event_format(tracing_subscriber::fmt::format().with_line_number(true)),
        )
        .with(EnvFilter::from_env("IROH_NET_LOG"))
        .init();
}
