use safer_ffi::{prelude::*, vec};

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
                derp_url: addr
                    .derp_url
                    .map(|u| u.url.clone().expect("url not initialized")),
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
            derp_url: addr
                .info
                .derp_url
                .map(|url| Box::new(Url { url: Some(url) }).into()),
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

/// Get the nth direct addresses of this peer.
///
/// Panics if i is larger than the available addrs.
#[ffi_export]
pub fn node_addr_direct_addresses_nth(addr: &NodeAddr, i: usize) -> &SocketAddr {
    &addr.direct_addresses[i]
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
/// Formats the given socket addr as a string
///
/// Result must be freed with `rust_free_string`
#[ffi_export]
pub fn socket_addr_as_str(addr: &SocketAddr) -> char_p::Box {
    addr.addr.to_string().try_into().unwrap()
}

#[ffi_export]
pub fn socket_addr_default() -> repr_c::Box<SocketAddr> {
    Box::new(SocketAddr {
        addr: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        )),
    })
    .into()
}

#[ffi_export]
pub fn socket_addr_free(addr: repr_c::Box<SocketAddr>) {
    drop(addr);
}

/// Try to parse a url from a string.
#[ffi_export]
pub fn socket_addr_from_string(
    input: char_p::Ref<'_>,
    out: &mut repr_c::Box<SocketAddr>,
) -> AddrResult {
    match input.to_str().parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            out.addr = addr;
            AddrResult::Ok
        }
        Err(_err) => AddrResult::InvalidSocketAddr,
    }
}

/// Represents a valid URL.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Url {
    url: Option<url::Url>,
}

/// Creates an initialized but invalid Url.
#[ffi_export]
pub fn url_default() -> repr_c::Box<Url> {
    Box::<Url>::default().into()
}

/// Formats the given url as a string
///
/// Result must be freed with `rust_free_string`
#[ffi_export]
pub fn url_as_str(url: &Url) -> char_p::Box {
    url.url
        .as_ref()
        .expect("url not initialized")
        .to_string()
        .try_into()
        .unwrap()
}

#[derive_ReprC]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AddrResult {
    /// Everything is ok.
    Ok = 0,
    /// Url was invalid.
    InvalidUrl,
    /// SocketAddr was invalid.
    InvalidSocketAddr,
}

/// Try to parse a url from a string.
#[ffi_export]
pub fn url_from_string(input: char_p::Ref<'_>, out: &mut repr_c::Box<Url>) -> AddrResult {
    match input.to_str().parse::<url::Url>() {
        Ok(url) => {
            out.url.replace(url);
            AddrResult::Ok
        }
        Err(_err) => AddrResult::InvalidUrl,
    }
}
