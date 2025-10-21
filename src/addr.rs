use iroh::{RelayUrl, TransportAddr};
use iroh_tickets::endpoint::EndpointTicket;
use safer_ffi::{prelude::*, vec};

use crate::key::PublicKey;

/// A peer and it's addressing information.
#[derive_ReprC]
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EndpointAddr {
    /// The endpoint's public key.
    pub id: PublicKey,
    /// The peers relay urls.
    pub relay_urls: vec::Vec<repr_c::Box<Url>>,
    /// The peers IP addresses
    pub ip_addrs: vec::Vec<repr_c::Box<SocketAddr>>,
}

impl PartialEq for EndpointAddr {
    fn eq(&self, other: &Self) -> bool {
        let a: iroh::EndpointAddr = self.clone().into();
        let b: iroh::EndpointAddr = other.clone().into();
        a.eq(&b)
    }
}

impl From<EndpointAddr> for iroh::EndpointAddr {
    fn from(addr: EndpointAddr) -> Self {
        let ip_addrs = addr.ip_addrs.into_iter().map(|a| TransportAddr::Ip(a.addr));
        let relay_urls = addr
            .relay_urls
            .into_iter()
            .filter_map(|url| url.url.clone().map(TransportAddr::Relay));

        iroh::EndpointAddr::from_parts(addr.id.into(), relay_urls.chain(ip_addrs))
    }
}

impl From<iroh::EndpointAddr> for EndpointAddr {
    fn from(addr: iroh::EndpointAddr) -> Self {
        let ip_addrs = addr
            .ip_addrs()
            .map(|addr| Box::new(SocketAddr { addr: *addr }).into())
            .collect::<Vec<_>>()
            .into();
        EndpointAddr {
            id: addr.id.into(),
            relay_urls: addr
                .relay_urls()
                .map(|url| {
                    Box::new(Url {
                        url: Some(url.clone()),
                    })
                    .into()
                })
                .collect::<Vec<_>>()
                .into(),
            ip_addrs,
        }
    }
}

/// Create a new addr with no details.
///
/// Must be freed using `endpoint_addr_free`.
#[ffi_export]
pub fn endpoint_addr_new(id: PublicKey) -> EndpointAddr {
    EndpointAddr {
        id,
        relay_urls: vec::Vec::EMPTY,
        ip_addrs: vec::Vec::EMPTY,
    }
}

/// Create a an empty (invalid) addr with no details.
///
/// Must be freed using `endpoint_addr_free`.
#[ffi_export]
pub fn endpoint_addr_default() -> EndpointAddr {
    EndpointAddr {
        id: PublicKey::default(),
        relay_urls: vec::Vec::EMPTY,
        ip_addrs: vec::Vec::EMPTY,
    }
}

/// Parses the full endpoint addr string representation.
#[ffi_export]
pub fn endpoint_addr_from_string(input: char_p::Ref<'_>, out: &mut EndpointAddr) -> AddrResult {
    let ticket: Result<EndpointTicket, _> = input.to_str().parse();
    match ticket {
        Ok(ticket) => {
            *out = ticket.endpoint_addr().clone().into();
            AddrResult::Ok
        }
        Err(_err) => AddrResult::InvalidEndpointAddr,
    }
}

/// Formats the given endpoint addr as a string.
///
/// Result must be freed with `rust_free_string`
#[ffi_export]
pub fn endpoint_addr_as_str(addr: &EndpointAddr) -> char_p::Box {
    let addr: iroh::EndpointAddr = addr.clone().into();
    EndpointTicket::new(addr).to_string().try_into().unwrap()
}

/// Free the endpoint addr.
#[ffi_export]
pub fn endpoint_addr_free(endpoint_addr: EndpointAddr) {
    drop(endpoint_addr)
}

/// Add a relay url to the peer's addr info.
#[ffi_export]
pub fn endpoint_addr_add_relay_url(addr: &mut EndpointAddr, relay_url: repr_c::Box<Url>) {
    addr.relay_urls.with_rust_mut(|addrs| {
        addrs.push(relay_url);
    });
}

/// Add the given direct addresses to the peer's addr info.
#[ffi_export]
pub fn endpoint_addr_add_ip_addrs(
    endpoint_addr: &mut EndpointAddr,
    address: repr_c::Box<SocketAddr>,
) {
    endpoint_addr.ip_addrs.with_rust_mut(|addrs| {
        addrs.push(address);
    });
}

/// Get the nth direct addresses of this peer.
#[ffi_export]
pub fn endpoint_addr_ip_addrs_nth(addr: &EndpointAddr, i: usize) -> Option<&SocketAddr> {
    addr.ip_addrs.get(i).map(|addr| &**addr)
}

/// Get the relay url of this peer.
#[ffi_export]
pub fn endpoint_addr_relay_urls_nth(addr: &EndpointAddr, i: usize) -> Option<&repr_c::Box<Url>> {
    addr.relay_urls.get(i)
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
    /// The endpoint addr was invalid.
    InvalidEndpointAddr,
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
    fn test_roundrip_string_endpoint_addr() {
        let mut endpoint_addr = endpoint_addr_default();
        endpoint_addr.id = public_key_default();
        endpoint_addr_add_relay_url(
            &mut endpoint_addr,
            Box::new(Url::from("http://test.com".parse::<RelayUrl>().unwrap())).into(),
        );
        endpoint_addr_add_ip_addrs(
            &mut endpoint_addr,
            Box::new(SocketAddr::from(
                "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))
            .into(),
        );

        dbg!(&endpoint_addr);
        let string = endpoint_addr_as_str(&endpoint_addr);

        let mut back = endpoint_addr_default();
        let res = endpoint_addr_from_string(string.as_ref(), &mut back);
        assert_eq!(res, AddrResult::Ok);
        assert_eq!(back, endpoint_addr);
    }
}
