use std::ops::Deref;

use safer_ffi::prelude::*;
use safer_ffi::vec;

use crate::key::secret_key_generate;
use crate::key::SecretKey;
use crate::util::TOKIO_EXECUTOR;

/// Configuration options for the MagicEndpoint.
#[derive_ReprC]
#[repr(C)]
pub struct MagicEndpointConfig {
    pub derp_mode: DerpMode,
    pub alpn_protocols: vec::Vec<vec::Vec<u8>>,
    pub secret_key: repr_c::Box<SecretKey>,
}

/// The options to configure derp.
#[derive_ReprC]
#[repr(u8)]
pub enum DerpMode {
    /// Derp mode is entirely disabled
    Disabled,
    /// Default derp map is used.
    Default,
    /// Default derp map, but only used for stun.
    /// Not yet implemented
    StunOnly,
}

impl From<DerpMode> for iroh_net::derp::DerpMode {
    fn from(value: DerpMode) -> Self {
        match value {
            DerpMode::Disabled => iroh_net::derp::DerpMode::Disabled,
            DerpMode::Default => iroh_net::derp::DerpMode::Default,
            DerpMode::StunOnly => unimplemented!("stun only is not implemented yet"),
        }
    }
}

/// Generate a default magic endpoint configuration.
#[ffi_export]
pub fn magic_endpoint_config_default() -> MagicEndpointConfig {
    MagicEndpointConfig {
        derp_mode: DerpMode::Default,
        alpn_protocols: vec::Vec::EMPTY,
        secret_key: secret_key_generate(),
    }
}

/// Generate a default endpoint.
///
/// Must be freed using `magic_endpoint_free`.
#[ffi_export]
pub fn magic_endpoint_default() -> repr_c::Box<MagicEndpoint> {
    Box::new(MagicEndpoint {
        ep: None
    }).into()
}

/// Frees the magic endpoint.
#[ffi_export]
pub fn magic_endpoint_free(ep: repr_c::Box<MagicEndpoint>) {
    drop(ep);
}

/// An endpoint that leverages a quic endpoint, backed by a magic socket.
#[derive_ReprC]
#[repr(opaque)]
pub struct MagicEndpoint {
    ep: Option<iroh_net::magic_endpoint::MagicEndpoint>,
}

/// Result of dealing with a magic endpoint.
#[derive_ReprC]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MagicEndpointResult {
    /// Everything is ok
    Ok = 0,
    /// Failed to bind.
    BindError,
}

#[ffi_export]
pub fn magic_endpoint_bind(
    config: MagicEndpointConfig,
    port: u16,
    out: &mut repr_c::Box<MagicEndpoint>,
) -> MagicEndpointResult {
    let mut alpn_protocols = Vec::with_capacity(config.alpn_protocols.len());
    for protocol in config.alpn_protocols.iter() {
        alpn_protocols.push(protocol.to_vec());
    }

    TOKIO_EXECUTOR.block_on(async move {
        let builder = iroh_net::magic_endpoint::MagicEndpointBuilder::default()
            .derp_mode(config.derp_mode.into())
            .alpns(alpn_protocols)
            .secret_key(config.secret_key.deref().into())
            .bind(port)
            .await;

        match builder {
            Ok(ep) => {
                out.ep.replace(ep);
                MagicEndpointResult::Ok
            }
            Err(_err) => {
                MagicEndpointResult::BindError
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() {
        let config = magic_endpoint_config_default();
        let mut ep = magic_endpoint_default();
        let bind_res = magic_endpoint_bind(config, 0, &mut ep);
        assert_eq!(bind_res, MagicEndpointResult::Ok);
    }
}
