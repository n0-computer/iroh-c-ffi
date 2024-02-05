use safer_ffi::{prelude::*, slice, vec};

use crate::key::PublicKey;

/// A peer and it's addressing information.
#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct NodeAddr {
    /// The node's public key.
    pub node_id: PublicKey,
    /// The peer's home DERP url.
    pub derp_url: Option<repr_c::Box<Url>>,
    /// Socket addresses where the peer might be reached directly.
    pub direct_addresses: vec::Vec<repr_c::Box<SocketAddr>>,
}

impl From<NodeAddr> for iroh_net::magic_endpoint::NodeAddr {
    fn from(addr: NodeAddr) -> Self {
        let direct_addresses = addr.direct_addresses.iter().map(|a| a.addr).collect();
        iroh_net::magic_endpoint::NodeAddr {
            node_id: addr.node_id.into(),
            info: iroh_net::magic_endpoint::AddrInfo {
                derp_url: addr.derp_url.map(|u| u.url.clone()),
                direct_addresses,
            },
        }
    }
}

impl From<iroh_net::magic_endpoint::NodeAddr> for NodeAddr {
    fn from(addr: iroh_net::magic_endpoint::NodeAddr) -> Self {
        let direct_addresses = addr
            .info
            .direct_addresses
            .into_iter()
            .map(|addr| Box::new(SocketAddr { addr }).into())
            .collect::<Vec<_>>()
            .into();
        NodeAddr {
            node_id: addr.node_id.into(),
            derp_url: addr.info.derp_url.map(|url| Box::new(Url { url }).into()),
            direct_addresses,
        }
    }
}

/// Create a new addr with no details.
///
/// Must be freed using `node_addr_free`.
#[ffi_export]
pub fn node_addr_new(node_id: PublicKey) -> NodeAddr {
    NodeAddr {
        node_id,
        derp_url: None,
        direct_addresses: vec::Vec::EMPTY,
    }
}

/// Create a an empty (invalid) addr with no details.
///
/// Must be freed using `node_addr_free`.
#[ffi_export]
pub fn node_addr_default() -> NodeAddr {
    NodeAddr {
        node_id: PublicKey::default(),
        derp_url: None,
        direct_addresses: vec::Vec::EMPTY,
    }
}

/// Free the node addr.
#[ffi_export]
pub fn node_addr_free(node_addr: NodeAddr) {
    drop(node_addr)
}

/// Add a derp url to the peer's addr info.
#[ffi_export]
pub fn node_addr_add_derp_url(addr: &mut NodeAddr, derp_url: repr_c::Box<Url>) {
    addr.derp_url.replace(derp_url);
}

/// Add the given direct addresses to the peer's addr info.
#[ffi_export]
pub fn node_addr_add_direct_address(node_addr: &mut NodeAddr, address: repr_c::Box<SocketAddr>) {
    node_addr.direct_addresses.with_rust_mut(|addrs| {
        addrs.push(address);
    });
}

/// Get the direct addresses of this peer.
///
/// Result must be freed with `free_vec_socket_addr`.
#[ffi_export]
pub fn node_addr_direct_addresses(
    addr: &NodeAddr,
) -> slice::slice_ref<'_, repr_c::Box<SocketAddr>> {
    addr.direct_addresses.as_ref()
}

/// Get the derp url of this peer.
#[ffi_export]
pub fn node_addr_derp_url(addr: &NodeAddr) -> Option<&repr_c::Box<Url>> {
    addr.derp_url.as_ref()
}

/// Represents an IPv4 or IPv6 address, including a port number.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddr {
    addr: std::net::SocketAddr,
}

/// Represents a valid URL.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    url: url::Url,
}
