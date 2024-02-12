use std::ops::Deref;

use anyhow::Context;
use safer_ffi::{prelude::*, slice, vec};

use crate::addr::NodeAddr;
use crate::key::{secret_key_generate, SecretKey};
use crate::stream::{RecvStream, SendStream};
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
#[derive(Debug, Copy, Clone)]
pub enum DerpMode {
    /// Derp mode is entirely disabled
    Disabled,
    /// Default derp map is used.
    Default,
}

impl From<DerpMode> for iroh_net::derp::DerpMode {
    fn from(value: DerpMode) -> Self {
        match value {
            DerpMode::Disabled => iroh_net::derp::DerpMode::Disabled,
            DerpMode::Default => iroh_net::derp::DerpMode::Default,
        }
    }
}

/// Frees the magic endpoint config.
#[ffi_export]
pub fn magic_endpoint_config_free(config: MagicEndpointConfig) {
    drop(config);
}

/// Generate a default magic endpoint configuration.
///
/// Must be freed using `magic_endpoing_config_free`.
#[ffi_export]
pub fn magic_endpoint_config_default() -> MagicEndpointConfig {
    MagicEndpointConfig {
        derp_mode: DerpMode::Default,
        alpn_protocols: vec::Vec::EMPTY,
        secret_key: secret_key_generate(),
    }
}

/// Add the given ALPN to the list of accepted ALPNs.
#[ffi_export]
pub fn magic_endpoint_config_add_alpn(
    config: &mut MagicEndpointConfig,
    alpn: slice::slice_ref<'_, u8>,
) {
    config.alpn_protocols.with_rust_mut(|alpns| {
        alpns.push(alpn.to_vec().into());
    });
}

/// Generate a default endpoint.
///
/// Must be freed using `magic_endpoint_free`.
#[ffi_export]
pub fn magic_endpoint_default() -> repr_c::Box<MagicEndpoint> {
    Box::new(MagicEndpoint { ep: None }).into()
}

/// Frees the magic endpoint.
#[ffi_export]
pub fn magic_endpoint_free(ep: repr_c::Box<MagicEndpoint>) {
    drop(ep);
}

/// Let the endpoint know that the underlying network conditions might have changed.
///
/// This really only needs to be called on android,
/// Ref https://developer.android.com/training/monitoring-device-state/connectivity-status-type
#[ffi_export]
pub fn magic_endpoint_network_change(ep: &repr_c::Box<MagicEndpoint>) {
    TOKIO_EXECUTOR.block_on(async move {
        ep.ep
            .as_ref()
            .expect("endpoint not initialized")
            .network_change()
            .await;
    });
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
    /// Failed to accept a uni directional stream,
    AcceptUniFailed,
    /// Failed to connect and establish a uni directional stream.
    ConnectUniError,
    /// Unable to retrive node addr.
    AddrError,
    /// Error while sending data.
    SendError,
    /// Error while reading data.
    ReadError,
}

/// Attempts to bind the endpoint to the given port.
///
/// If the port is already in use, a random port will be used.
///
/// Blocks the current thread.
#[ffi_export]
pub fn magic_endpoint_bind(
    config: &MagicEndpointConfig,
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
            Err(_err) => MagicEndpointResult::BindError,
        }
    })
}

/// Accept a new connection and a uni directional stream on this endpoint.
///
/// Blocks the current thread.
#[ffi_export]
pub fn magic_endpoint_accept_uni(
    ep: &repr_c::Box<MagicEndpoint>,
    expected_alpn: slice::slice_ref<'_, u8>,
    out: &mut repr_c::Box<RecvStream>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let conn = ep
            .ep
            .as_ref()
            .expect("endpoint not initalized")
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
        let (remote_node_id, alpn, connection) = iroh_net::magic_endpoint::accept_conn(conn)
            .await
            .context("accept_conn")?;
        if alpn.as_bytes() != expected_alpn.as_slice() {
            anyhow::bail!("unexpected alpn {}", alpn);
        }
        let recv_stream = connection.accept_uni().await.context("accept_uni")?;

        anyhow::Ok((remote_node_id, recv_stream))
    });

    match res {
        Ok((_remote_node_id, recv_stream)) => {
            out.stream.replace(recv_stream);
            MagicEndpointResult::Ok
        }
        Err(_err) => MagicEndpointResult::AcceptUniFailed,
    }
}

/// An established connection.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Default)]
pub struct Connection {
    connection: Option<quinn::Connection>,
}

/// Result must be freed using `connection_free`.
#[ffi_export]
pub fn connection_default() -> repr_c::Box<Connection> {
    Box::<Connection>::default().into()
}

/// Frees the connection.
#[ffi_export]
pub fn connection_free(conn: repr_c::Box<Connection>) {
    drop(conn);
}

/// Send a single datgram (unreliably).
///
/// Data must not be larger than the available `max_datagram` size.
#[ffi_export]
pub fn magic_endpoint_connection_write_datagram(
    connection: &repr_c::Box<Connection>,
    data: slice::slice_ref<'_, u8>,
) -> MagicEndpointResult {
    // TODO: is there a way to avoid this allocation?
    let data = bytes::Bytes::copy_from_slice(data.as_ref());
    let res = connection
        .connection
        .as_ref()
        .expect("connection not initialized")
        .send_datagram(data);

    match res {
        Ok(()) => MagicEndpointResult::Ok,
        Err(_err) => {
            dbg!(_err);
            MagicEndpointResult::SendError
        }
    }
}

/// Reads a datgram.
///
/// Data must not be larger than the available `max_datagram` size.
///
/// Blocks the current thread until a datagram is received.
#[ffi_export]
pub fn magic_endpoint_connection_read_datagram(
    connection: &repr_c::Box<Connection>,
    data: &mut vec::Vec<u8>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        connection
            .connection
            .as_ref()
            .expect("connection not initialized")
            .read_datagram()
            .await
    });

    match res {
        Ok(bytes) => {
            data.with_rust_mut(|v| {
                v.resize(bytes.len(), 0u8);
                v.copy_from_slice(&bytes);
            });
            MagicEndpointResult::Ok
        }
        Err(_err) => {
            dbg!(_err);
            MagicEndpointResult::ReadError
        }
    }
}

/// Returns the maximum datagram size. `0` if it is not supported.
#[ffi_export]
pub fn magic_endpoint_connection_max_datagram_size(connection: &repr_c::Box<Connection>) -> usize {
    connection
        .connection
        .as_ref()
        .expect("connection not initialized")
        .max_datagram_size()
        .unwrap_or(0)
}

/// Accept a new connection on this endpoint.
///
/// Blocks the current thread until a connection is established.
#[ffi_export]
pub fn magic_endpoint_accept(
    ep: &repr_c::Box<MagicEndpoint>,
    expected_alpn: slice::slice_ref<'_, u8>,
    out: &mut repr_c::Box<Connection>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let conn = ep
            .ep
            .as_ref()
            .expect("endpoint not initalized")
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
        let (remote_node_id, alpn, connection) = iroh_net::magic_endpoint::accept_conn(conn)
            .await
            .context("accept_conn")?;
        if alpn.as_bytes() != expected_alpn.as_slice() {
            anyhow::bail!("unexpected alpn {}", alpn);
        }
        anyhow::Ok((remote_node_id, connection))
    });

    match res {
        Ok((_remote_node_id, connection)) => {
            out.connection.replace(connection);
            MagicEndpointResult::Ok
        }
        Err(_err) => MagicEndpointResult::AcceptUniFailed,
    }
}

/// Connect the given node and establish a uni directional connection.
///
/// Blocks the current thread until the connection is established.
#[ffi_export]
pub fn magic_endpoint_connect_uni(
    ep: &repr_c::Box<MagicEndpoint>,
    alpn: slice::slice_ref<'_, u8>,
    node_addr: NodeAddr,
    out: &mut repr_c::Box<SendStream>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let node_addr = node_addr.into();
        let conn = ep
            .ep
            .as_ref()
            .expect("endpoint not initialized")
            .connect(node_addr, alpn.as_ref())
            .await?;
        let stream = conn.open_uni().await?;

        anyhow::Ok(stream)
    });

    match res {
        Ok(stream) => {
            out.stream.replace(stream);
            MagicEndpointResult::Ok
        }
        Err(_err) => MagicEndpointResult::ConnectUniError,
    }
}

/// Connects to the given node.
///
/// Blocks until the connection is established.
#[ffi_export]
pub fn magic_endpoint_connect(
    ep: &repr_c::Box<MagicEndpoint>,
    alpn: slice::slice_ref<'_, u8>,
    node_addr: NodeAddr,
    out: &mut repr_c::Box<Connection>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let node_addr = node_addr.into();
        let conn = ep
            .ep
            .as_ref()
            .expect("endpoint not initialized")
            .connect(node_addr, alpn.as_ref())
            .await?;

        anyhow::Ok(conn)
    });

    match res {
        Ok(connection) => {
            out.connection.replace(connection);
            MagicEndpointResult::Ok
        }
        Err(_err) => MagicEndpointResult::ConnectUniError,
    }
}

/// Get the the node dialing information of this magic endpoint.
#[ffi_export]
pub fn magic_endpoint_my_addr(
    ep: &repr_c::Box<MagicEndpoint>,
    out: &mut NodeAddr,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let addr = ep
            .ep
            .as_ref()
            .expect("endpoint not initialized")
            .my_addr()
            .await?;
        anyhow::Ok(addr)
    });

    match res {
        Ok(addr) => {
            *out = addr.into();
            MagicEndpointResult::Ok
        }
        Err(_err) => MagicEndpointResult::AddrError,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        addr::node_addr_default,
        stream::{
            recv_stream_default, recv_stream_read, send_stream_default, send_stream_finish,
            send_stream_write,
        },
        util::rust_buffer_alloc,
    };

    use super::*;

    #[test]
    fn stream_uni() {
        let alpn: vec::Vec<u8> = b"/cool/alpn/1".to_vec().into();
        // create config
        let mut config_server = magic_endpoint_config_default();
        magic_endpoint_config_add_alpn(&mut config_server, alpn.as_ref().into());

        let mut config_client = magic_endpoint_config_default();
        magic_endpoint_config_add_alpn(&mut config_client, alpn.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();

        // setup server
        let alpn_s = alpn.clone();
        let server_thread = std::thread::spawn(move || {
            // create magic endpoint and bind
            let mut ep = magic_endpoint_default();
            let bind_res = magic_endpoint_bind(&config_server, 0, &mut ep);
            assert_eq!(bind_res, MagicEndpointResult::Ok);

            let mut node_addr = node_addr_default();
            let res = magic_endpoint_my_addr(&ep, &mut node_addr);
            assert_eq!(res, MagicEndpointResult::Ok);

            s.send(node_addr).unwrap();

            // accept connection
            println!("[s] accepting conn");
            let mut recv_stream = recv_stream_default();
            let accept_res = magic_endpoint_accept_uni(&ep, alpn_s.as_ref(), &mut recv_stream);
            assert_eq!(accept_res, MagicEndpointResult::Ok);

            println!("[s] reading");

            let mut recv_buffer = vec![0u8; 1024];
            let read_res = recv_stream_read(&mut recv_stream, (&mut recv_buffer[..]).into());
            assert!(read_res > 0);
            assert_eq!(
                std::str::from_utf8(&recv_buffer[..read_res as usize]).unwrap(),
                "hello world"
            );
        });

        // setup client
        let client_thread = std::thread::spawn(move || {
            // create magic endpoint and bind
            let mut ep = magic_endpoint_default();
            let bind_res = magic_endpoint_bind(&config_client, 0, &mut ep);
            assert_eq!(bind_res, MagicEndpointResult::Ok);

            // wait for addr from server
            let node_addr = r.recv().unwrap();

            println!("[c] dialing");
            // connect to server
            let mut send_stream = send_stream_default();
            let connect_res =
                magic_endpoint_connect_uni(&ep, alpn.as_ref(), node_addr, &mut send_stream);
            assert_eq!(connect_res, MagicEndpointResult::Ok);

            println!("[c] sending");
            let send_res = send_stream_write(&mut send_stream, b"hello world"[..].into());
            assert_eq!(send_res, MagicEndpointResult::Ok);

            let finish_res = send_stream_finish(send_stream);
            assert_eq!(finish_res, MagicEndpointResult::Ok);
        });

        server_thread.join().unwrap();
        client_thread.join().unwrap();
    }

    #[test]
    fn datagram() {
        let alpn: vec::Vec<u8> = b"/cool/alpn/1".to_vec().into();
        // create config
        let mut config_server = magic_endpoint_config_default();
        magic_endpoint_config_add_alpn(&mut config_server, alpn.as_ref().into());

        let mut config_client = magic_endpoint_config_default();
        magic_endpoint_config_add_alpn(&mut config_client, alpn.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();
        let (server_s, server_r) = std::sync::mpsc::channel();

        // setup server
        let alpn_s = alpn.clone();
        let server_thread = std::thread::spawn(move || {
            // create magic endpoint and bind
            let mut ep = magic_endpoint_default();
            let bind_res = magic_endpoint_bind(&config_server, 0, &mut ep);
            assert_eq!(bind_res, MagicEndpointResult::Ok);

            let mut node_addr = node_addr_default();
            let res = magic_endpoint_my_addr(&ep, &mut node_addr);
            assert_eq!(res, MagicEndpointResult::Ok);

            s.send(node_addr).unwrap();

            // accept connection
            println!("[s] accepting conn");
            let mut conn = connection_default();
            let accept_res = magic_endpoint_accept(&ep, alpn_s.as_ref(), &mut conn);
            assert_eq!(accept_res, MagicEndpointResult::Ok);

            println!("[s] reading");

            let mut recv_buffer = rust_buffer_alloc(1024);
            let read_res = magic_endpoint_connection_read_datagram(&conn, &mut recv_buffer);
            assert_eq!(read_res, MagicEndpointResult::Ok);
            assert_eq!(std::str::from_utf8(&recv_buffer).unwrap(), "hello world");
            server_s.send(()).unwrap();
        });

        // setup client
        let client_thread = std::thread::spawn(move || {
            // create magic endpoint and bind
            let mut ep = magic_endpoint_default();
            let bind_res = magic_endpoint_bind(&config_client, 0, &mut ep);
            assert_eq!(bind_res, MagicEndpointResult::Ok);

            // wait for addr from server
            let node_addr = r.recv().unwrap();

            println!("[c] dialing");
            // connect to server
            let mut conn = connection_default();
            let connect_res = magic_endpoint_connect(&ep, alpn.as_ref(), node_addr, &mut conn);
            assert_eq!(connect_res, MagicEndpointResult::Ok);

            println!("[c] sending");
            let max_datagram = magic_endpoint_connection_max_datagram_size(&conn);
            assert!(max_datagram > 0);
            dbg!(max_datagram);
            let send_res =
                magic_endpoint_connection_write_datagram(&mut conn, b"hello world"[..].into());
            assert_eq!(send_res, MagicEndpointResult::Ok);

            // wait for the server to have received
            server_r.recv().unwrap();
        });

        server_thread.join().unwrap();
        client_thread.join().unwrap();
    }
}
