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

/// Returns the public key as a lowercase hex string.
///
/// Result must be freed using `rust_free_string`
#[ffi_export]
pub fn public_key_as_str(key: &PublicKey) -> char_p::Box {
    iroh::PublicKey::from(key).to_string().try_into().unwrap()
}

/// Deprecated: use `public_key_as_str`. Despite the name, the result is hex.
///
/// Result must be freed using `rust_free_string`
#[ffi_export]
pub fn public_key_as_base32(key: &PublicKey) -> char_p::Box {
    public_key_as_str(key)
}

/// Generate a default (invalid) public key.
///
/// Result must be freed using `public_key_free`.
#[ffi_export]
pub fn public_key_default() -> PublicKey {
    PublicKey::default()
}

/// Parses the public key from lowercase hex or unpadded RFC 4648 base32.
#[ffi_export]
pub fn public_key_from_string(raw_key: char_p::Ref<'_>, out: &mut PublicKey) -> KeyResult {
    let key: Result<iroh::PublicKey, _> = raw_key.to_str().parse();

    match key {
        Ok(key) => {
            out.key.copy_from_slice(key.as_bytes());
            KeyResult::Ok
        }
        Err(_) => KeyResult::InvalidPublicKey,
    }
}

/// Deprecated: use `public_key_from_string`. Accepts lowercase hex or unpadded base32.
#[ffi_export]
pub fn public_key_from_base32(raw_key: char_p::Ref<'_>, out: &mut PublicKey) -> KeyResult {
    public_key_from_string(raw_key, out)
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
        key: iroh::SecretKey::generate(),
    })
    .into()
}

/// Parses the secret key from lowercase hex or unpadded RFC 4648 base32.
#[ffi_export]
pub fn secret_key_from_string(
    raw_key: char_p::Ref<'_>,
    out: &mut repr_c::Box<SecretKey>,
) -> KeyResult {
    let key: Result<iroh::SecretKey, _> = raw_key.to_str().parse();

    match key {
        Ok(key) => {
            out.key = key;
            KeyResult::Ok
        }
        Err(_) => KeyResult::InvalidSecretKey,
    }
}

/// Deprecated: use `secret_key_from_string`. Accepts lowercase hex or unpadded base32.
#[ffi_export]
pub fn secret_key_from_base32(
    raw_key: char_p::Ref<'_>,
    out: &mut repr_c::Box<SecretKey>,
) -> KeyResult {
    secret_key_from_string(raw_key, out)
}

/// Generates a new key with default OS randomness.
///
/// Result must be freed using `secret_key_free`
#[ffi_export]
pub fn secret_key_generate() -> repr_c::Box<SecretKey> {
    Box::new(SecretKey {
        key: iroh::SecretKey::generate(),
    })
    .into()
}

/// Returns the secret key as a lowercase hex string.
///
/// Result must be freed using `rust_free_string`
#[ffi_export]
pub fn secret_key_as_str(key: &SecretKey) -> char_p::Box {
    data_encoding::HEXLOWER
        .encode(&key.key.to_bytes())
        .try_into()
        .unwrap()
}

/// Deprecated: use `secret_key_as_str`. Despite the name, the result is hex.
///
/// Result must be freed using `rust_free_string`
#[ffi_export]
pub fn secret_key_as_base32(key: &SecretKey) -> char_p::Box {
    secret_key_as_str(key)
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

        let secret_key_str = secret_key_as_str(&secret_key);
        let mut secret_key_back = secret_key_default();
        let res = secret_key_from_string(secret_key_str.as_ref(), &mut secret_key_back);
        assert_eq!(res, KeyResult::Ok);
        assert_eq!(secret_key.key.to_bytes(), secret_key_back.key.to_bytes());

        let public_key = secret_key_public(&secret_key);
        let public_key_str = public_key_as_str(&public_key);
        let mut public_key_back = public_key_default();
        let res = public_key_from_string(public_key_str.as_ref(), &mut public_key_back);
        assert_eq!(res, KeyResult::Ok);
        assert_eq!(public_key, public_key_back);
    }

    #[test]
    fn key_string_formats() {
        let secret_key = secret_key_generate();
        let public_key = secret_key_public(&secret_key);

        assert_eq!(
            secret_key_as_str(&secret_key).to_str(),
            data_encoding::HEXLOWER.encode(&secret_key.key.to_bytes()),
        );
        assert_eq!(
            public_key_as_str(&public_key).to_str(),
            data_encoding::HEXLOWER.encode(&public_key.key),
        );

        let base32 = data_encoding::BASE32_NOPAD.encode(&public_key.key);
        for s in [base32.clone(), base32.to_lowercase()] {
            let s = char_p::new(s);
            let mut back = public_key_default();
            let res = public_key_from_string(s.as_ref(), &mut back);
            assert_eq!(res, KeyResult::Ok);
            assert_eq!(back, public_key);
        }

        let padded = char_p::new(data_encoding::BASE32.encode(&public_key.key));
        let mut back = public_key_default();
        let res = public_key_from_string(padded.as_ref(), &mut back);
        assert_eq!(res, KeyResult::InvalidPublicKey);

        let upper_hex = char_p::new(public_key_as_str(&public_key).to_str().to_uppercase());
        let mut back = public_key_default();
        let res = public_key_from_string(upper_hex.as_ref(), &mut back);
        assert_eq!(res, KeyResult::InvalidPublicKey);

        let secret_base32 =
            char_p::new(data_encoding::BASE32_NOPAD.encode(&secret_key.key.to_bytes()));
        let mut secret_back = secret_key_default();
        let res = secret_key_from_string(secret_base32.as_ref(), &mut secret_back);
        assert_eq!(res, KeyResult::Ok);
        assert_eq!(secret_key.key.to_bytes(), secret_back.key.to_bytes());
    }

    #[test]
    fn invalid_keys() {
        let invalid = char_p::new("not a key");

        let mut public_key = public_key_default();
        let res = public_key_from_string(invalid.as_ref(), &mut public_key);
        assert_eq!(res, KeyResult::InvalidPublicKey);

        let mut secret_key = secret_key_default();
        let res = secret_key_from_string(invalid.as_ref(), &mut secret_key);
        assert_eq!(res, KeyResult::InvalidSecretKey);
    }
}
