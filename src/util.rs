use safer_ffi::prelude::*;

/// Frees a Rust-allocated string.
#[ffi_export]
pub fn rust_free_string(string: char_p::Box) {
    drop(string)
}
