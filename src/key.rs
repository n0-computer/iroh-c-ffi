use safer_ffi::prelude::*;

/// Result of handling key material.
#[derive_ReprC]
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum KeyResult {
    /// Everything is ok.
    Ok = 0,
    /// Invalid public key material.
    InvalidPublicKey,
    /// Invalid secret key material.
    InvalidSecretKey,
}

/// A public key.
#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublicKey {
    key: [u8; 32],
}

/// Free the passed in key.
#[ffi_export]
pub fn public_key_free(_key: PublicKey) {
    // nothing to do
}

/// Returns the public key as a base32 string.
///
/// Result must be freed using `rust_free_string`
#[ffi_export]
pub fn public_key_as_base32(key: &PublicKey) -> char_p::Box {
    iroh::PublicKey::from(key).to_string().try_into().unwrap()
}

/// Generate a default (invalid) public key.
///
/// Result must be freed using `public_key_free`.
#[ffi_export]
pub fn public_key_default() -> PublicKey {
    PublicKey::default()
}

/// Parses the public key from a base32 string.
#[ffi_export]
pub fn public_key_from_base32(raw_key: char_p::Ref<'_>, out: &mut PublicKey) -> KeyResult {
    let key: Result<iroh::PublicKey, _> = raw_key.to_str().parse();

    match key {
        Ok(key) => {
            out.key.copy_from_slice(key.as_bytes());
            KeyResult::Ok
        }
        Err(_) => KeyResult::InvalidPublicKey,
    }
}

impl From<iroh::PublicKey> for PublicKey {
    fn from(key: iroh::PublicKey) -> Self {
        PublicKey {
            key: *key.as_bytes(),
        }
    }
}

impl From<PublicKey> for iroh::PublicKey {
    fn from(key: PublicKey) -> Self {
        iroh::PublicKey::try_from(&key.key).unwrap()
    }
}

impl From<&PublicKey> for iroh::PublicKey {
    fn from(key: &PublicKey) -> Self {
        iroh::PublicKey::try_from(&key.key).unwrap()
    }
}

/// A secret key.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone)]
pub struct SecretKey {
    key: iroh::SecretKey,
}

/// Free the passed in key.
#[ffi_export]
pub fn secret_key_free(key: repr_c::Box<SecretKey>) {
    drop(key);
}

/// Generate a default secret key.
///
/// Result must be freed using `secret_key_free`.
#[ffi_export]
pub fn secret_key_default() -> repr_c::Box<SecretKey> {
    Box::new(SecretKey {
        key: iroh::SecretKey::generate(rand::thread_rng()),
    })
    .into()
}

/// Parses the secret key from a base32 string.
#[ffi_export]
pub fn secret_key_from_base32(
    raw_key: char_p::Ref<'_>,
    out: &mut repr_c::Box<SecretKey>,
) -> KeyResult {
    let key: Result<iroh::SecretKey, _> = raw_key.to_str().parse();

    match key {
        Ok(key) => {
            out.key = key;
            KeyResult::Ok
        }
        Err(_) => KeyResult::InvalidPublicKey,
    }
}

/// Generates a new key with default OS randomness.
///
/// Result must be freed using `secret_key_free`
#[ffi_export]
pub fn secret_key_generate() -> repr_c::Box<SecretKey> {
    Box::new(SecretKey {
        key: iroh::SecretKey::generate(rand::thread_rng()),
    })
    .into()
}

/// Returns the secret key as a base32 string.
///
/// Result must be freed using `rust_free_string`
#[ffi_export]
pub fn secret_key_as_base32(key: &SecretKey) -> char_p::Box {
    key.key.to_string().try_into().unwrap()
}

/// The public key for this secret key.
///
/// Result must be freed using `public_key_free`
#[ffi_export]
pub fn secret_key_public(key: &SecretKey) -> PublicKey {
    key.key.public().into()
}

impl From<iroh::SecretKey> for SecretKey {
    fn from(key: iroh::SecretKey) -> Self {
        SecretKey { key }
    }
}

impl From<SecretKey> for iroh::SecretKey {
    fn from(key: SecretKey) -> Self {
        key.key
    }
}

impl From<&SecretKey> for iroh::SecretKey {
    fn from(key: &SecretKey) -> Self {
        key.key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_key_ops() {
        let secret_key = secret_key_generate();

        let secret_key_str = secret_key_as_base32(&secret_key);
        let mut secret_key_back = secret_key_default();
        let res = secret_key_from_base32(secret_key_str.as_ref(), &mut secret_key_back);
        assert_eq!(res, KeyResult::Ok);

        let public_key = secret_key_public(&secret_key);
        let public_key_str = public_key_as_base32(&public_key);
        let mut public_key_back = public_key_default();
        let res = public_key_from_base32(public_key_str.as_ref(), &mut public_key_back);
        assert_eq!(res, KeyResult::Ok);
        assert_eq!(public_key, public_key_back);
    }
}
