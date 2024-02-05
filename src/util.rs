use once_cell::sync::Lazy;
use safer_ffi::prelude::*;

/// Frees a Rust-allocated string.
#[ffi_export]
pub fn rust_free_string(string: char_p::Box) {
    drop(string)
}

pub(crate) static TOKIO_EXECUTOR: Lazy<tokio::runtime::Runtime> =
    Lazy::new(|| tokio::runtime::Runtime::new().unwrap());
