pub mod addr;
pub mod key;
pub mod magic_endpoint;
pub mod stream;
pub mod util;

/// The following function is only necessary for the header generation.
#[cfg(feature = "headers")]
pub fn generate_headers() -> std::io::Result<()> {
    use safer_ffi::headers;

    headers::builder()
        .with_language(headers::Language::C)
        .with_naming_convention(headers::NamingConvention::Prefix("iroh".into()))
        .to_file("irohnet.h")?
        .generate()
}
