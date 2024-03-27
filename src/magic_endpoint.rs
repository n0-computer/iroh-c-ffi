use std::ffi::c_void;
use std::ops::Deref;
use std::time::Duration;

use anyhow::Context;
use safer_ffi::{prelude::*, slice, vec};
use tokio::sync::RwLock;

use crate::addr::NodeAddr;
use crate::key::{secret_key_generate, SecretKey};
use crate::stream::{RecvStream, SendStream};
use crate::util::TOKIO_EXECUTOR;

/// Configuration options for the MagicEndpoint.
#[derive_ReprC]
#[repr(C)]
pub struct MagicEndpointConfig {
    pub relay_mode: RelayMode,
    pub alpn_protocols: vec::Vec<vec::Vec<u8>>,
    pub secret_key: repr_c::Box<SecretKey>,
}

/// The options to configure relay.
#[derive_ReprC]
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum RelayMode {
    /// Relay mode is entirely disabled
    Disabled,
    /// Default relay map is used.
    Default,
}

impl From<RelayMode> for iroh_net::relay::RelayMode {
    fn from(value: RelayMode) -> Self {
        match value {
            RelayMode::Disabled => iroh_net::relay::RelayMode::Disabled,
            RelayMode::Default => iroh_net::relay::RelayMode::Default,
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
        relay_mode: RelayMode::Default,
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

/// Sets the given secret key to use.
#[ffi_export]
pub fn magic_endpoint_config_add_secret_key(
    config: &mut MagicEndpointConfig,
    secret_key: repr_c::Box<SecretKey>,
) {
    config.secret_key = secret_key;
}

/// Generate a default endpoint.
///
/// Must be freed using `magic_endpoint_free`.
#[ffi_export]
pub fn magic_endpoint_default() -> repr_c::Box<MagicEndpoint> {
    Box::new(MagicEndpoint { ep: None.into() }).into()
}

/// Frees the magic endpoint.
#[ffi_export]
pub fn magic_endpoint_free(ep: repr_c::Box<MagicEndpoint>) {
    TOKIO_EXECUTOR.block_on(async move {
        let _ = ep.ep.write().await.take();
    });
}

/// Let the endpoint know that the underlying network conditions might have changed.
///
/// This really only needs to be called on android,
/// Ref https://developer.android.com/training/monitoring-device-state/connectivity-status-type
#[ffi_export]
pub fn magic_endpoint_network_change(ep: &repr_c::Box<MagicEndpoint>) {
    TOKIO_EXECUTOR.block_on(async move {
        ep.ep
            .read()
            .await
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
    ep: RwLock<Option<iroh_net::magic_endpoint::MagicEndpoint>>,
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
    /// Failed to accept a connection.
    AcceptFailed,
    /// Failed to accept a uni directional stream,
    AcceptUniFailed,
    /// Failed to accept a bi directional stream,
    AcceptBiFailed,
    /// Failed to connect and establish a uni directional stream.
    ConnectUniError,
    /// Unable to retrive node addr.
    AddrError,
    /// Error while sending data.
    SendError,
    /// Error while reading data.
    ReadError,
    /// Timeout elapsed.
    Timeout,
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
    out: &repr_c::Box<MagicEndpoint>,
) -> MagicEndpointResult {
    let mut alpn_protocols = Vec::with_capacity(config.alpn_protocols.len());
    for protocol in config.alpn_protocols.iter() {
        alpn_protocols.push(protocol.to_vec());
    }

    TOKIO_EXECUTOR.block_on(async move {
        let builder = iroh_net::magic_endpoint::MagicEndpointBuilder::default()
            .relay_mode(config.relay_mode.into())
            .alpns(alpn_protocols)
            .secret_key(config.secret_key.deref().into())
            .bind(port)
            .await;

        match builder {
            Ok(ep) => {
                out.ep.write().await.replace(ep);
                MagicEndpointResult::Ok
            }
            Err(_err) => MagicEndpointResult::BindError,
        }
    })
}

/// Accepts a uni directional stream on this connection.
///
/// Blocks the current thread.
#[ffi_export]
pub fn connection_accept_uni(
    conn: &repr_c::Box<Connection>,
    out: &mut repr_c::Box<RecvStream>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let recv_stream = conn
            .connection
            .read()
            .await
            .as_ref()
            .expect("connection not initialized")
            .accept_uni()
            .await
            .context("accept_uni")?;

        anyhow::Ok(recv_stream)
    });

    match res {
        Ok(recv_stream) => {
            out.stream.replace(recv_stream);
            MagicEndpointResult::Ok
        }
        Err(_err) => MagicEndpointResult::AcceptUniFailed,
    }
}

/// Accept a bi directional stream on this endpoint.
///
/// Blocks the current thread.
#[ffi_export]
pub fn connection_accept_bi(
    conn: &repr_c::Box<Connection>,
    send: &mut repr_c::Box<SendStream>,
    recv: &mut repr_c::Box<RecvStream>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let (send_stream, recv_stream) = conn
            .connection
            .read()
            .await
            .as_ref()
            .expect("connection not initialized")
            .accept_bi()
            .await
            .context("accept_uni")?;

        anyhow::Ok((send_stream, recv_stream))
    });

    match res {
        Ok((send_stream, recv_stream)) => {
            send.stream.replace(send_stream);
            recv.stream.replace(recv_stream);
            MagicEndpointResult::Ok
        }
        Err(_err) => MagicEndpointResult::AcceptBiFailed,
    }
}

/// An established connection.
#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Default)]
pub struct Connection {
    connection: RwLock<Option<quinn::Connection>>,
}

/// Result must be freed using `connection_free`.
#[ffi_export]
pub fn connection_default() -> repr_c::Box<Connection> {
    Box::<Connection>::default().into()
}

/// Frees the connection.
#[ffi_export]
pub fn connection_free(conn: repr_c::Box<Connection>) {
    TOKIO_EXECUTOR.block_on(async move {
        let _ = conn.connection.write().await.take();
    });
}

/// Estimated roundtrip time for the current connection in milli seconds.
#[ffi_export]
pub fn connection_rtt(conn: &repr_c::Box<Connection>) -> u64 {
    TOKIO_EXECUTOR.block_on(async move {
        conn.connection
            .read()
            .await
            .as_ref()
            .expect("connection not initialized")
            .rtt()
            .as_millis() as u64
    })
}

/// Send a single datgram (unreliably).
///
/// Data must not be larger than the available `max_datagram` size.
#[ffi_export]
pub fn connection_write_datagram(
    connection: &repr_c::Box<Connection>,
    data: slice::slice_ref<'_, u8>,
) -> MagicEndpointResult {
    // TODO: is there a way to avoid this allocation?
    let data = bytes::Bytes::copy_from_slice(data.as_ref());
    TOKIO_EXECUTOR.block_on(async move {
        let res = connection
            .connection
            .read()
            .await
            .as_ref()
            .expect("connection not initialized")
            .send_datagram(data);

        match res {
            Ok(()) => MagicEndpointResult::Ok,
            Err(_err) => MagicEndpointResult::SendError,
        }
    })
}

/// Reads a datgram.
///
/// Data must not be larger than the available `max_datagram` size.
///
/// Blocks the current thread until a datagram is received.
#[ffi_export]
pub fn connection_read_datagram(
    connection: &repr_c::Box<Connection>,
    data: &mut vec::Vec<u8>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        connection
            .connection
            .read()
            .await
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
        Err(_err) => MagicEndpointResult::ReadError,
    }
}

/// Reads a datgram, with timeout.
///
/// Will block at most `timeout` milliseconds.
///
/// Data received will not be larger than the available `max_datagram` size.
///
/// Blocks the current thread until a datagram is received or the timeout is expired.
#[ffi_export]
pub fn connection_read_datagram_timeout(
    connection: &repr_c::Box<Connection>,
    data: &mut vec::Vec<u8>,
    timeout_ms: u64,
) -> MagicEndpointResult {
    let timeout = Duration::from_millis(timeout_ms);
    let res = TOKIO_EXECUTOR.block_on(async move {
        tokio::time::timeout(timeout, async move {
            connection
                .connection
                .read()
                .await
                .as_ref()
                .expect("connection not initialized")
                .read_datagram()
                .await
        })
        .await
    });

    match res {
        Ok(Ok(bytes)) => {
            data.with_rust_mut(|v| {
                v.resize(bytes.len(), 0u8);
                v.copy_from_slice(&bytes);
            });
            MagicEndpointResult::Ok
        }
        Ok(Err(_err)) => MagicEndpointResult::ReadError,
        Err(_err) => MagicEndpointResult::Timeout,
    }
}

/// Returns the maximum datagram size. `0` if it is not supported.
#[ffi_export]
pub fn connection_max_datagram_size(connection: &repr_c::Box<Connection>) -> usize {
    TOKIO_EXECUTOR.block_on(async move {
        connection
            .connection
            .read()
            .await
            .as_ref()
            .expect("connection not initialized")
            .max_datagram_size()
            .unwrap_or(0)
    })
}

/// Accept a new connection on this endpoint.
///
/// Blocks the current thread until a connection is established.
#[ffi_export]
pub fn magic_endpoint_accept(
    ep: &repr_c::Box<MagicEndpoint>,
    expected_alpn: slice::slice_ref<'_, u8>,
    out: &repr_c::Box<Connection>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let conn = ep
            .ep
            .read()
            .await
            .as_ref()
            .expect("endpoint not initalized")
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
        let (_remote_node_id, alpn, connection) = iroh_net::magic_endpoint::accept_conn(conn)
            .await
            .context("accept_conn")?;
        if alpn.as_bytes() != expected_alpn.as_slice() {
            anyhow::bail!("unexpected alpn {}", alpn);
        }
        out.connection.write().await.replace(connection);
        anyhow::Ok(())
    });

    match res {
        Ok(()) => MagicEndpointResult::Ok,
        Err(_err) => MagicEndpointResult::AcceptFailed,
    }
}

/// Accept a new connection on this endpoint.
///
/// Does not prespecify the ALPN, and but rather returns it.
///
/// Blocks the current thread until a connection is established.
#[ffi_export]
pub fn magic_endpoint_accept_any(
    ep: &repr_c::Box<MagicEndpoint>,
    alpn_out: &mut vec::Vec<u8>,
    out: &repr_c::Box<Connection>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let conn = ep
            .ep
            .read()
            .await
            .as_ref()
            .expect("endpoint not initalized")
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
        let (_remote_node_id, alpn, connection) = iroh_net::magic_endpoint::accept_conn(conn)
            .await
            .context("accept_conn")?;

        alpn_out.with_rust_mut(|v| {
            *v = alpn.as_bytes().to_vec();
        });
        out.connection.write().await.replace(connection);
        anyhow::Ok(())
    });

    match res {
        Ok(()) => MagicEndpointResult::Ok,
        Err(_err) => MagicEndpointResult::AcceptFailed,
    }
}

/// Accept a new connection on this endpoint.
///
/// Does not prespecify the ALPN, and but rather returns it.
///
/// Does not block, the provided callback will be called the next time a new connection is accepted or
/// when an error occurs.
/// `ctx` is passed along to the callback, to allow passing context, it must be thread safe as the callback is
/// called from another thread.
#[ffi_export]
pub fn magic_endpoint_accept_any_cb(
    ep: repr_c::Box<MagicEndpoint>,
    ctx: *const c_void,
    cb: unsafe extern "C" fn(
        ctx: *const c_void,
        err: MagicEndpointResult,
        alpn: vec::Vec<u8>,
        conn: repr_c::Box<Connection>,
    ),
) {
    // hack around the fact that `*const c_void` is not Send
    struct CtxPtr(*const c_void);
    unsafe impl Send for CtxPtr {}
    let ctx_ptr = CtxPtr(ctx);

    TOKIO_EXECUTOR.spawn(async move {
        // make the compiler happy
        let _ = &ctx_ptr;
        async fn connect(
            ep: repr_c::Box<MagicEndpoint>,
        ) -> anyhow::Result<(String, quinn::Connection)> {
            let conn = ep
                .ep
                .read()
                .await
                .as_ref()
                .expect("endpoint not initalized")
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
            let (_remote_node_id, alpn, connection) = iroh_net::magic_endpoint::accept_conn(conn)
                .await
                .context("accept_conn")?;

            Ok((alpn, connection))
        }

        match connect(ep).await {
            Ok((alpn, connection)) => {
                let alpn = alpn.as_bytes().to_vec().into();
                let conn = Box::new(Connection {
                    connection: Some(connection).into(),
                })
                .into();
                unsafe {
                    cb(ctx_ptr.0, MagicEndpointResult::Ok, alpn, conn);
                }
            }
            Err(_err) => unsafe {
                cb(
                    ctx_ptr.0,
                    MagicEndpointResult::AcceptFailed,
                    vec::Vec::EMPTY,
                    Box::<Connection>::default().into(),
                );
            },
        }
    });
}

/// Establish a uni directional connection.
///
/// Blocks the current thread until the connection is established.
#[ffi_export]
pub fn connection_open_uni(
    conn: &repr_c::Box<Connection>,
    out: &mut repr_c::Box<SendStream>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let stream = conn
            .connection
            .read()
            .await
            .as_ref()
            .expect("connection not initialized")
            .open_uni()
            .await?;

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

/// Establish a bi directional connection.
///
/// Blocks the current thread until the connection is established.
#[ffi_export]
pub fn connection_open_bi(
    conn: &repr_c::Box<Connection>,
    send: &mut repr_c::Box<SendStream>,
    recv: &mut repr_c::Box<RecvStream>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let (send_stream, recv_stream) = conn
            .connection
            .read()
            .await
            .as_ref()
            .expect("connection not initialized")
            .open_bi()
            .await?;

        anyhow::Ok((send_stream, recv_stream))
    });

    match res {
        Ok((send_stream, recv_stream)) => {
            send.stream.replace(send_stream);
            recv.stream.replace(recv_stream);
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
    out: &repr_c::Box<Connection>,
) -> MagicEndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let node_addr = node_addr.into();
        let conn = ep
            .ep
            .read()
            .await
            .as_ref()
            .expect("endpoint not initialized")
            .connect(node_addr, alpn.as_ref())
            .await?;
        out.connection.write().await.replace(conn);

        anyhow::Ok(())
    });

    match res {
        Ok(()) => MagicEndpointResult::Ok,
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
            .read()
            .await
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
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn stream_uni_a_b() {
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
            let mut conn = connection_default();
            let accept_res = magic_endpoint_accept(&ep, alpn_s.as_ref(), &mut conn);
            assert_eq!(accept_res, MagicEndpointResult::Ok);

            let mut recv_stream = recv_stream_default();
            let accept_res = connection_accept_uni(&conn, &mut recv_stream);
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
            let mut conn = connection_default();
            let connect_res = magic_endpoint_connect(&ep, alpn.as_ref(), node_addr, &mut conn);
            assert_eq!(connect_res, MagicEndpointResult::Ok);

            let mut send_stream = send_stream_default();
            let open_res = connection_open_uni(&conn, &mut send_stream);
            assert_eq!(open_res, MagicEndpointResult::Ok);

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
    fn stream_uni_b_a() {
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
            let mut conn = connection_default();
            let accept_res = magic_endpoint_accept(&ep, alpn_s.as_ref(), &mut conn);
            assert_eq!(accept_res, MagicEndpointResult::Ok);

            println!("[s] opening uni");
            let mut send_stream = send_stream_default();
            let accept_res = connection_open_uni(&conn, &mut send_stream);
            assert_eq!(accept_res, MagicEndpointResult::Ok);

            println!("[s] sending");

            let send_res = send_stream_write(&mut send_stream, b"hello world"[..].into());
            assert_eq!(send_res, MagicEndpointResult::Ok);

            let finish_res = send_stream_finish(send_stream);
            assert_eq!(finish_res, MagicEndpointResult::Ok);
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

            println!("[c] accepting uni");
            let mut recv_stream = recv_stream_default();
            let open_res = connection_accept_uni(&conn, &mut recv_stream);
            assert_eq!(open_res, MagicEndpointResult::Ok);

            println!("[c] reading");
            let mut recv_buffer = vec![0u8; 1024];
            let read_res = recv_stream_read(&mut recv_stream, (&mut recv_buffer[..]).into());
            assert!(read_res > 0);
            assert_eq!(
                std::str::from_utf8(&recv_buffer[..read_res as usize]).unwrap(),
                "hello world"
            );
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
            let read_res = connection_read_datagram(&conn, &mut recv_buffer);
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
            let max_datagram = connection_max_datagram_size(&conn);
            assert!(max_datagram > 0);
            dbg!(max_datagram);
            let send_res = connection_write_datagram(&mut conn, b"hello world"[..].into());
            assert_eq!(send_res, MagicEndpointResult::Ok);

            // wait for the server to have received
            server_r.recv().unwrap();
        });

        server_thread.join().unwrap();
        client_thread.join().unwrap();
    }

    #[test]
    fn stream_bi() {
        let alpn: vec::Vec<u8> = b"/cool/alpn/1".to_vec().into();
        // create config
        let mut config_server = magic_endpoint_config_default();
        magic_endpoint_config_add_alpn(&mut config_server, alpn.as_ref().into());

        let mut config_client = magic_endpoint_config_default();
        magic_endpoint_config_add_alpn(&mut config_client, alpn.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();
        let (client_s, client_r) = std::sync::mpsc::channel();

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
            let res = magic_endpoint_accept(&ep, alpn_s.as_ref(), &mut conn);
            assert_eq!(res, MagicEndpointResult::Ok);

            let mut send_stream = send_stream_default();
            let mut recv_stream = recv_stream_default();
            let accept_res = connection_accept_bi(&conn, &mut send_stream, &mut recv_stream);
            assert_eq!(accept_res, MagicEndpointResult::Ok);

            println!("[s] reading");

            let mut recv_buffer = vec![0u8; 1024];
            let read_res = recv_stream_read(&mut recv_stream, (&mut recv_buffer[..]).into());
            assert!(read_res > 0);
            assert_eq!(
                std::str::from_utf8(&recv_buffer[..read_res as usize]).unwrap(),
                "hello world"
            );

            println!("[s] sending");
            let send_res = send_stream_write(&mut send_stream, b"hello client"[..].into());
            assert_eq!(send_res, MagicEndpointResult::Ok);

            let res = send_stream_finish(send_stream);
            assert_eq!(res, MagicEndpointResult::Ok);
            client_r.recv().unwrap();
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

            let mut send_stream = send_stream_default();
            let mut recv_stream = recv_stream_default();
            let open_res = connection_open_bi(&conn, &mut send_stream, &mut recv_stream);
            assert_eq!(open_res, MagicEndpointResult::Ok);

            println!("[c] sending");
            let send_res = send_stream_write(&mut send_stream, b"hello world"[..].into());
            assert_eq!(send_res, MagicEndpointResult::Ok);

            println!("[c] reading");

            let mut recv_buffer = vec![0u8; 1024];
            let read_res = recv_stream_read(&mut recv_stream, (&mut recv_buffer[..]).into());
            assert!(read_res > 0);
            assert_eq!(
                std::str::from_utf8(&recv_buffer[..read_res as usize]).unwrap(),
                "hello client"
            );

            let finish_res = send_stream_finish(send_stream);
            assert_eq!(finish_res, MagicEndpointResult::Ok);
            client_s.send(()).unwrap();
        });

        server_thread.join().unwrap();
        client_thread.join().unwrap();
    }

    #[test]
    fn test_two_connections() {
        let alpn1: vec::Vec<u8> = b"/cool/alpn/1".to_vec().into();
        let alpn2: vec::Vec<u8> = b"/cool/alpn/2".to_vec().into();

        // create config
        let mut config_server = magic_endpoint_config_default();
        magic_endpoint_config_add_alpn(&mut config_server, alpn1.as_ref().into());
        magic_endpoint_config_add_alpn(&mut config_server, alpn2.as_ref().into());

        let mut config_client = magic_endpoint_config_default();
        magic_endpoint_config_add_alpn(&mut config_client, alpn1.as_ref().into());
        magic_endpoint_config_add_alpn(&mut config_client, alpn2.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();
        let (client1_s, client1_r) = std::sync::mpsc::channel();
        let (client2_s, client2_r) = std::sync::mpsc::channel();

        // setup server
        let alpn1_s = alpn1.clone();
        let alpn2_s = alpn2.clone();
        let server_thread = std::thread::spawn(move || {
            // create magic endpoint and bind
            let ep = magic_endpoint_default();
            let bind_res = magic_endpoint_bind(&config_server, 0, &ep);
            assert_eq!(bind_res, MagicEndpointResult::Ok);

            let mut node_addr = node_addr_default();
            let res = magic_endpoint_my_addr(&ep, &mut node_addr);
            assert_eq!(res, MagicEndpointResult::Ok);

            s.send(node_addr).unwrap();

            let mut handles = Vec::new();
            let ep = Arc::new(ep);
            let clients = Arc::new(Mutex::new(vec![client1_r, client2_r]));
            for i in 0..2 {
                let ep = ep.clone();
                let alpn1_s = alpn1_s.clone();
                let alpn2_s = alpn2_s.clone();

                let clients = clients.clone();
                handles.push(std::thread::spawn(move || {
                    // accept connection
                    println!("[s][{i}] accepting conn");
                    let mut conn = connection_default();
                    let mut alpn = vec::Vec::EMPTY;
                    let res = magic_endpoint_accept_any(&ep, &mut alpn, &mut conn);
                    assert_eq!(res, MagicEndpointResult::Ok);

                    let (j, client_r) = if alpn.as_ref() == alpn1_s.as_ref() {
                        (0, clients.lock().unwrap().remove(0))
                    } else if alpn.as_ref() == alpn2_s.as_ref() {
                        (1, clients.lock().unwrap().pop().unwrap())
                    } else {
                        panic!("unexpectd alpn: {:?}", alpn);
                    };

                    let mut send_stream = send_stream_default();
                    let mut recv_stream = recv_stream_default();
                    let accept_res =
                        connection_accept_bi(&conn, &mut send_stream, &mut recv_stream);
                    assert_eq!(accept_res, MagicEndpointResult::Ok);

                    println!("[s][{j}] reading");

                    let mut recv_buffer = vec![0u8; 1024];
                    let read_res =
                        recv_stream_read(&mut recv_stream, (&mut recv_buffer[..]).into());
                    assert!(read_res > 0);
                    assert_eq!(
                        std::str::from_utf8(&recv_buffer[..read_res as usize]).unwrap(),
                        &format!("hello world {j}"),
                    );

                    println!("[s][{j}] sending");
                    let send_res = send_stream_write(
                        &mut send_stream,
                        format!("hello client {j}").as_bytes().into(),
                    );
                    assert_eq!(send_res, MagicEndpointResult::Ok);

                    let res = send_stream_finish(send_stream);
                    assert_eq!(res, MagicEndpointResult::Ok);
                    client_r.recv().unwrap();
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }
        });

        // setup client
        let client_thread = std::thread::spawn(move || {
            // create magic endpoint and bind
            let ep = magic_endpoint_default();
            let bind_res = magic_endpoint_bind(&config_client, 0, &ep);
            assert_eq!(bind_res, MagicEndpointResult::Ok);

            // wait for addr from server
            let node_addr = r.recv().unwrap();

            let mut handles = Vec::new();
            let ep = Arc::new(ep);
            let clients = [client1_s, client2_s];

            for (i, client_s) in clients.into_iter().enumerate() {
                let ep = ep.clone();
                let alpn1 = alpn1.clone();
                let alpn2 = alpn2.clone();
                let node_addr = node_addr.clone();

                handles.push(std::thread::spawn(move || {
                    // wait for a moment to make sure the server is ready
                    std::thread::sleep(std::time::Duration::from_millis(100));

                    println!("[c][{i}] dialing");
                    // connect to server
                    let mut conn = connection_default();
                    let alpn = if i == 0 { alpn1 } else { alpn2 };
                    let connect_res =
                        magic_endpoint_connect(&ep, alpn.as_ref(), node_addr, &mut conn);
                    assert_eq!(connect_res, MagicEndpointResult::Ok);

                    let mut send_stream = send_stream_default();
                    let mut recv_stream = recv_stream_default();
                    let open_res = connection_open_bi(&conn, &mut send_stream, &mut recv_stream);
                    assert_eq!(open_res, MagicEndpointResult::Ok);

                    println!("[c][{i}] sending");
                    let send_res = send_stream_write(
                        &mut send_stream,
                        format!("hello world {i}").as_bytes().into(),
                    );
                    assert_eq!(send_res, MagicEndpointResult::Ok);

                    println!("[c][{i}] reading");

                    let mut recv_buffer = vec![0u8; 1024];
                    let read_res =
                        recv_stream_read(&mut recv_stream, (&mut recv_buffer[..]).into());
                    assert!(read_res > 0);
                    assert_eq!(
                        std::str::from_utf8(&recv_buffer[..read_res as usize]).unwrap(),
                        &format!("hello client {i}")
                    );

                    let finish_res = send_stream_finish(send_stream);
                    assert_eq!(finish_res, MagicEndpointResult::Ok);
                    client_s.send(()).unwrap();
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }
        });

        server_thread.join().unwrap();
        client_thread.join().unwrap();
    }
}
