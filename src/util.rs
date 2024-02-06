use once_cell::sync::Lazy;
use safer_ffi::{prelude::*, vec};

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

pub(crate) static TOKIO_EXECUTOR: Lazy<tokio::runtime::Runtime> =
    Lazy::new(|| tokio::runtime::Runtime::new().unwrap());
