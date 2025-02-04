use iroh::RelayUrl;
use iroh_base::ticket::NodeTicket;
use safer_ffi::{prelude::*, vec};

use crate::key::PublicKey;

/// A peer and it's addressing information.
#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct NodeAddr {
    /// The node's public key.
    pub node_id: PublicKey,
    /// The peer's home RELAY url.
    pub relay_url: Option<repr_c::Box<Url>>,
    /// Socket addresses where the peer might be reached directly.
    pub direct_addresses: vec::Vec<repr_c::Box<SocketAddr>>,
}

impl PartialEq for NodeAddr {
    fn eq(&self, other: &Self) -> bool {
        let a: iroh::NodeAddr = self.clone().into();
        let b: iroh::NodeAddr = other.clone().into();
        a.eq(&b)
    }
}

impl From<NodeAddr> for iroh::NodeAddr {
    fn from(addr: NodeAddr) -> Self {
        let direct_addresses = addr.direct_addresses.iter().map(|a| a.addr).collect();
        iroh::NodeAddr {
            node_id: addr.node_id.into(),
            relay_url: addr
                .relay_url
                .map(|u| u.url.clone().expect("url not initialized")),
            direct_addresses,
        }
    }
}

impl From<iroh::NodeAddr> for NodeAddr {
    fn from(addr: iroh::NodeAddr) -> Self {
        let direct_addresses = addr
            .direct_addresses
            .into_iter()
            .map(|addr| Box::new(SocketAddr { addr }).into())
            .collect::<Vec<_>>()
            .into();
        NodeAddr {
            node_id: addr.node_id.into(),
            relay_url: addr
                .relay_url
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
        relay_url: None,
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
        relay_url: None,
        direct_addresses: vec::Vec::EMPTY,
    }
}

/// Parses the full node addr string representation.
#[ffi_export]
pub fn node_addr_from_string(input: char_p::Ref<'_>, out: &mut NodeAddr) -> AddrResult {
    let ticket: Result<NodeTicket, _> = input.to_str().parse();
    match ticket {
        Ok(ticket) => {
            *out = ticket.node_addr().clone().into();
            AddrResult::Ok
        }
        Err(_err) => AddrResult::InvalidNodeAddr,
    }
}

/// Formats the given node addr as a string.
///
/// Result must be freed with `rust_free_string`
#[ffi_export]
pub fn node_addr_as_str(addr: &NodeAddr) -> char_p::Box {
    let addr: iroh::NodeAddr = addr.clone().into();
    NodeTicket::new(addr).to_string().try_into().unwrap()
}

/// Free the node addr.
#[ffi_export]
pub fn node_addr_free(node_addr: NodeAddr) {
    drop(node_addr)
}

/// Add a relay url to the peer's addr info.
#[ffi_export]
pub fn node_addr_add_relay_url(addr: &mut NodeAddr, relay_url: repr_c::Box<Url>) {
    addr.relay_url.replace(relay_url);
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

/// Get the relay url of this peer.
#[ffi_export]
pub fn node_addr_relay_url(addr: &NodeAddr) -> Option<&repr_c::Box<Url>> {
    addr.relay_url.as_ref()
}

/// Represents an IPv4 or IPv6 address, including a port number.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddr {
    addr: std::net::SocketAddr,
}

impl From<std::net::SocketAddr> for SocketAddr {
    fn from(addr: std::net::SocketAddr) -> Self {
        SocketAddr { addr }
    }
}

/// Represents an IPv4 address, including a port number.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddrV4 {
    addr: std::net::SocketAddrV4,
}

impl From<std::net::SocketAddrV4> for SocketAddrV4 {
    fn from(addr: std::net::SocketAddrV4) -> Self {
        Self { addr }
    }
}

impl From<&SocketAddrV4> for std::net::SocketAddrV4 {
    fn from(value: &SocketAddrV4) -> Self {
        value.addr
    }
}

/// Represents an IPv6 address, including a port number.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketAddrV6 {
    addr: std::net::SocketAddrV6,
}

impl From<std::net::SocketAddrV6> for SocketAddrV6 {
    fn from(addr: std::net::SocketAddrV6) -> Self {
        Self { addr }
    }
}

impl From<&SocketAddrV6> for std::net::SocketAddrV6 {
    fn from(value: &SocketAddrV6) -> Self {
        value.addr
    }
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

/// Formats the given socket addr as a string
///
/// Result must be freed with `rust_free_string`
#[ffi_export]
pub fn socket_addr_v4_as_str(addr: &SocketAddrV4) -> char_p::Box {
    addr.addr.to_string().try_into().unwrap()
}

#[ffi_export]
pub fn socket_addr_v4_default() -> repr_c::Box<SocketAddrV4> {
    Box::new(SocketAddrV4 {
        addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
    })
    .into()
}

#[ffi_export]
pub fn socket_addr_v4_free(addr: repr_c::Box<SocketAddrV4>) {
    drop(addr);
}

/// Try to parse a url from a string.
#[ffi_export]
pub fn socket_addr_v4_from_string(
    input: char_p::Ref<'_>,
    out: &mut repr_c::Box<SocketAddrV4>,
) -> AddrResult {
    match input.to_str().parse::<std::net::SocketAddrV4>() {
        Ok(addr) => {
            out.addr = addr;
            AddrResult::Ok
        }
        Err(_err) => AddrResult::InvalidSocketAddr,
    }
}

/// Formats the given socket addr as a string
///
/// Result must be freed with `rust_free_string`
#[ffi_export]
pub fn socket_addr_v6_as_str(addr: &SocketAddrV6) -> char_p::Box {
    addr.addr.to_string().try_into().unwrap()
}

#[ffi_export]
pub fn socket_addr_v6_default() -> repr_c::Box<SocketAddrV6> {
    Box::new(SocketAddrV6 {
        addr: std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0),
    })
    .into()
}

#[ffi_export]
pub fn socket_addr_v6_free(addr: repr_c::Box<SocketAddrV6>) {
    drop(addr);
}

/// Try to parse a url from a string.
#[ffi_export]
pub fn socket_addr_v6_from_string(
    input: char_p::Ref<'_>,
    out: &mut repr_c::Box<SocketAddrV6>,
) -> AddrResult {
    match input.to_str().parse::<std::net::SocketAddrV6>() {
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
    url: Option<RelayUrl>,
}

impl From<RelayUrl> for Url {
    fn from(url: RelayUrl) -> Self {
        Url { url: Some(url) }
    }
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
    /// The node addr was invalid.
    InvalidNodeAddr,
}

/// Try to parse a url from a string.
#[ffi_export]
pub fn url_from_string(input: char_p::Ref<'_>, out: &mut repr_c::Box<Url>) -> AddrResult {
    match input.to_str().parse::<RelayUrl>() {
        Ok(url) => {
            out.url.replace(url);
            AddrResult::Ok
        }
        Err(_err) => AddrResult::InvalidUrl,
    }
}

#[cfg(test)]
mod tests {
    use crate::key::public_key_default;

    use super::*;

    #[test]
    fn test_roundrip_string_node_addr() {
        let mut node_addr = node_addr_default();
        node_addr.node_id = public_key_default();
        node_addr_add_relay_url(
            &mut node_addr,
            Box::new(Url::from("http://test.com".parse::<RelayUrl>().unwrap())).into(),
        );
        node_addr_add_direct_address(
            &mut node_addr,
            Box::new(SocketAddr::from(
                "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))
            .into(),
        );

        dbg!(&node_addr);
        let string = node_addr_as_str(&node_addr);

        let mut back = node_addr_default();
        let res = node_addr_from_string(string.as_ref(), &mut back);
        assert_eq!(res, AddrResult::Ok);
        assert_eq!(back, node_addr);
    }
}
