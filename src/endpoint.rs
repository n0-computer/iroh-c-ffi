use std::ffi::c_void;
use std::ops::Deref;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use safer_ffi::{prelude::*, slice, vec};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::addr::NodeAddr;
use crate::key::{secret_key_generate, SecretKey};
use crate::stream::{RecvStream, SendStream};
use crate::util::TOKIO_EXECUTOR;

/// Configuration options for the Endpoint.
#[derive_ReprC]
#[repr(C)]
pub struct EndpointConfig {
    pub relay_mode: RelayMode,
    pub alpn_protocols: vec::Vec<vec::Vec<u8>>,
    pub secret_key: repr_c::Box<SecretKey>,
    pub peers_data_path: Option<char_p::Box>,
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

/// Frees the iroh endpoint config.
#[ffi_export]
pub fn endpoint_config_free(config: EndpointConfig) {
    drop(config);
}

/// Generate a default endpoint configuration.
///
/// Must be freed using `endpoint_config_free`.
#[ffi_export]
pub fn endpoint_config_default() -> EndpointConfig {
    EndpointConfig {
        relay_mode: RelayMode::Default,
        alpn_protocols: vec::Vec::EMPTY,
        secret_key: secret_key_generate(),
        peers_data_path: None,
    }
}

/// Add the given ALPN to the list of accepted ALPNs.
#[ffi_export]
pub fn endpoint_config_add_alpn(config: &mut EndpointConfig, alpn: slice::slice_ref<'_, u8>) {
    config.alpn_protocols.with_rust_mut(|alpns| {
        alpns.push(alpn.to_vec().into());
    });
}

/// Set the given value as the storage path for peer data.
#[ffi_export]
pub fn endpoint_config_set_peers_data_path(config: &mut EndpointConfig, path: char_p::Ref<'_>) {
    config.peers_data_path = Some(path.to_owned());
}

/// Sets the given secret key to use.
#[ffi_export]
pub fn endpoint_config_add_secret_key(
    config: &mut EndpointConfig,
    secret_key: repr_c::Box<SecretKey>,
) {
    config.secret_key = secret_key;
}

/// Generate a default endpoint.
///
/// Must be freed using `endpoint_free`.
#[ffi_export]
pub fn endpoint_default() -> repr_c::Box<Endpoint> {
    Box::new(Endpoint { ep: None.into() }).into()
}

/// Frees the iroh endpoint.
#[ffi_export]
pub fn endpoint_free(ep: repr_c::Box<Endpoint>) {
    TOKIO_EXECUTOR.block_on(async move {
        let _ = ep.ep.write().await.take();
    });
}

/// Let the endpoint know that the underlying network conditions might have changed.
///
/// This really only needs to be called on android,
/// Ref https://developer.android.com/training/monitoring-device-state/connectivity-status-type
#[ffi_export]
pub fn endpoint_network_change(ep: &repr_c::Box<Endpoint>) {
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

/// An endpoint that leverages a quic endpoint, backed by a iroh socket.
#[derive_ReprC]
#[repr(opaque)]
pub struct Endpoint {
    ep: RwLock<Option<iroh_net::endpoint::Endpoint>>,
}

/// Result of dealing with a iroh endpoint.
#[derive_ReprC]
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EndpointResult {
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
    /// Failed to connect and establish a bi directional stream.
    ConnectBiError,
    /// Failed to connect.
    ConnectError,
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
pub fn endpoint_bind(
    config: &EndpointConfig,
    port: u16,
    out: &repr_c::Box<Endpoint>,
) -> EndpointResult {
    let mut alpn_protocols = Vec::with_capacity(config.alpn_protocols.len());
    for protocol in config.alpn_protocols.iter() {
        alpn_protocols.push(protocol.to_vec());
    }

    debug!(
        "binding with alpns: {:?}",
        alpn_protocols
            .iter()
            .map(|v| std::str::from_utf8(v.as_ref()))
            .collect::<Vec<_>>()
    );

    TOKIO_EXECUTOR.block_on(async move {
        let mut builder = iroh_net::endpoint::Builder::default()
            .relay_mode(config.relay_mode.into())
            .alpns(alpn_protocols)
            .secret_key(config.secret_key.deref().into());

        if let Some(ref path) = config.peers_data_path {
            let path: PathBuf = path.to_string().into();
            builder = builder.peers_data_path(path);
        }

        let builder = builder.bind(port).await;

        match builder {
            Ok(ep) => {
                out.ep.write().await.replace(ep);
                EndpointResult::Ok
            }
            Err(err) => {
                warn!("failed to bind {:?}", err);
                EndpointResult::BindError
            }
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
) -> EndpointResult {
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
            EndpointResult::Ok
        }
        Err(err) => {
            warn!("accept uni failed: {:?}", err);
            EndpointResult::AcceptUniFailed
        }
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
) -> EndpointResult {
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
            EndpointResult::Ok
        }
        Err(err) => {
            warn!("accept bi failed: {:?}", err);
            EndpointResult::AcceptBiFailed
        }
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
) -> EndpointResult {
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
            Ok(()) => EndpointResult::Ok,
            Err(err) => {
                warn!("send datagram failed: {:?}", err);
                EndpointResult::SendError
            }
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
) -> EndpointResult {
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
            EndpointResult::Ok
        }
        Err(err) => {
            warn!("read failed: {:?}", err);
            EndpointResult::ReadError
        }
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
) -> EndpointResult {
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
            EndpointResult::Ok
        }
        Ok(Err(err)) => {
            warn!("read failed: {:?}", err);
            EndpointResult::ReadError
        }
        Err(_err) => {
            warn!("read failed timeout");
            EndpointResult::Timeout
        }
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
pub fn endpoint_accept(
    ep: &repr_c::Box<Endpoint>,
    expected_alpn: slice::slice_ref<'_, u8>,
    out: &repr_c::Box<Connection>,
) -> EndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let mut conn = ep
            .ep
            .read()
            .await
            .as_ref()
            .expect("endpoint not initalized")
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
        let alpn = conn.alpn().await?;
        let connection = conn.await?;
        if alpn.as_bytes() != expected_alpn.as_slice() {
            anyhow::bail!("unexpected alpn {}", alpn);
        }
        out.connection.write().await.replace(connection);
        anyhow::Ok(())
    });

    match res {
        Ok(()) => EndpointResult::Ok,
        Err(err) => {
            warn!(
                "accept failed: {:?}: {:?}",
                std::str::from_utf8(expected_alpn.as_ref()),
                err
            );
            EndpointResult::AcceptFailed
        }
    }
}

/// Accept a new connection on this endpoint.
///
/// Does not prespecify the ALPN, and but rather returns it.
///
/// Blocks the current thread until a connection is established.
#[ffi_export]
pub fn endpoint_accept_any(
    ep: &repr_c::Box<Endpoint>,
    alpn_out: &mut vec::Vec<u8>,
    out: &repr_c::Box<Connection>,
) -> EndpointResult {
    let res = TOKIO_EXECUTOR.block_on(async move {
        let mut conn = ep
            .ep
            .read()
            .await
            .as_ref()
            .expect("endpoint not initalized")
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
        let alpn = conn.alpn().await?;
        let connection = conn.await?;

        alpn_out.with_rust_mut(|v| {
            *v = alpn.as_bytes().to_vec();
        });
        out.connection.write().await.replace(connection);
        anyhow::Ok(())
    });

    match res {
        Ok(()) => EndpointResult::Ok,
        Err(err) => {
            warn!("accept failed {:?}", err);
            EndpointResult::AcceptFailed
        }
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
pub fn endpoint_accept_any_cb(
    ep: repr_c::Box<Endpoint>,
    ctx: *const c_void,
    cb: unsafe extern "C" fn(
        ctx: *const c_void,
        err: EndpointResult,
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
        async fn connect(ep: repr_c::Box<Endpoint>) -> anyhow::Result<(String, quinn::Connection)> {
            let mut conn = ep
                .ep
                .read()
                .await
                .as_ref()
                .expect("endpoint not initalized")
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
            let alpn = conn.alpn().await?;
            let connection = conn.await?;
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
                    cb(ctx_ptr.0, EndpointResult::Ok, alpn, conn);
                }
            }
            Err(err) => unsafe {
                warn!("accept failed: {:?}", err);
                cb(
                    ctx_ptr.0,
                    EndpointResult::AcceptFailed,
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
) -> EndpointResult {
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
            EndpointResult::Ok
        }
        Err(err) => {
            warn!("open uni failed: {:?}", err);
            EndpointResult::ConnectUniError
        }
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
) -> EndpointResult {
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
            EndpointResult::Ok
        }
        Err(err) => {
            warn!("connect bi failed: {:?}", err);
            EndpointResult::ConnectBiError
        }
    }
}

/// Connects to the given node.
///
/// Blocks until the connection is established.
#[ffi_export]
pub fn endpoint_connect(
    ep: &repr_c::Box<Endpoint>,
    alpn: slice::slice_ref<'_, u8>,
    node_addr: NodeAddr,
    out: &repr_c::Box<Connection>,
) -> EndpointResult {
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
        Ok(()) => EndpointResult::Ok,
        Err(err) => {
            warn!("connect failed: {:?}", err);
            EndpointResult::ConnectError
        }
    }
}

/// Get the the node dialing information of this iroh endpoint.
#[ffi_export]
pub fn endpoint_my_addr(ep: &repr_c::Box<Endpoint>, out: &mut NodeAddr) -> EndpointResult {
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
            EndpointResult::Ok
        }
        Err(err) => {
            warn!("failed to retrieve addr: {:?}", err);
            EndpointResult::AddrError
        }
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
    fn test_config() {
        let mut config = endpoint_config_default();
        let alpn0: vec::Vec<u8> = b"/hello/world/1234".to_vec().into();
        let alpn1: vec::Vec<u8> = b"/ha/coo/12".to_vec().into();

        endpoint_config_add_alpn(&mut config, alpn0.as_ref().into());
        assert_eq!(config.alpn_protocols[0].as_ref(), alpn0.as_ref());
        assert_eq!(config.alpn_protocols[0].as_ref().len(), 17);

        endpoint_config_add_alpn(&mut config, alpn1.as_ref().into());
        assert_eq!(config.alpn_protocols[1].as_ref(), alpn1.as_ref());
        assert_eq!(config.alpn_protocols[1].as_ref().len(), 10);
    }

    #[test]
    fn stream_uni_a_b() {
        let alpn: vec::Vec<u8> = b"/cool/alpn/1".to_vec().into();
        // create config
        let mut config_server = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_server, alpn.as_ref().into());

        let mut config_client = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_client, alpn.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();

        // setup server
        let alpn_s = alpn.clone();
        let server_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let mut ep = endpoint_default();
            let bind_res = endpoint_bind(&config_server, 0, &mut ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            let mut node_addr = node_addr_default();
            let res = endpoint_my_addr(&ep, &mut node_addr);
            assert_eq!(res, EndpointResult::Ok);

            s.send(node_addr).unwrap();

            // accept connection
            println!("[s] accepting conn");
            let mut conn = connection_default();
            let accept_res = endpoint_accept(&ep, alpn_s.as_ref(), &mut conn);
            assert_eq!(accept_res, EndpointResult::Ok);

            let mut recv_stream = recv_stream_default();
            let accept_res = connection_accept_uni(&conn, &mut recv_stream);
            assert_eq!(accept_res, EndpointResult::Ok);

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
            // create iroh endpoint and bind
            let mut ep = endpoint_default();
            let bind_res = endpoint_bind(&config_client, 0, &mut ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            // wait for addr from server
            let node_addr = r.recv().unwrap();

            println!("[c] dialing");
            // connect to server
            let mut conn = connection_default();
            let connect_res = endpoint_connect(&ep, alpn.as_ref(), node_addr, &mut conn);
            assert_eq!(connect_res, EndpointResult::Ok);

            let mut send_stream = send_stream_default();
            let open_res = connection_open_uni(&conn, &mut send_stream);
            assert_eq!(open_res, EndpointResult::Ok);

            println!("[c] sending");
            let send_res = send_stream_write(&mut send_stream, b"hello world"[..].into());
            assert_eq!(send_res, EndpointResult::Ok);

            let finish_res = send_stream_finish(send_stream);
            assert_eq!(finish_res, EndpointResult::Ok);
        });

        server_thread.join().unwrap();
        client_thread.join().unwrap();
    }

    #[test]
    fn stream_uni_b_a() {
        let alpn: vec::Vec<u8> = b"/cool/alpn/1".to_vec().into();
        // create config
        let mut config_server = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_server, alpn.as_ref().into());

        let mut config_client = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_client, alpn.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();

        // setup server
        let alpn_s = alpn.clone();
        let server_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let mut ep = endpoint_default();
            let bind_res = endpoint_bind(&config_server, 0, &mut ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            let mut node_addr = node_addr_default();
            let res = endpoint_my_addr(&ep, &mut node_addr);
            assert_eq!(res, EndpointResult::Ok);

            s.send(node_addr).unwrap();

            // accept connection
            println!("[s] accepting conn");
            let mut conn = connection_default();
            let accept_res = endpoint_accept(&ep, alpn_s.as_ref(), &mut conn);
            assert_eq!(accept_res, EndpointResult::Ok);

            println!("[s] opening uni");
            let mut send_stream = send_stream_default();
            let accept_res = connection_open_uni(&conn, &mut send_stream);
            assert_eq!(accept_res, EndpointResult::Ok);

            println!("[s] sending");

            let send_res = send_stream_write(&mut send_stream, b"hello world"[..].into());
            assert_eq!(send_res, EndpointResult::Ok);

            let finish_res = send_stream_finish(send_stream);
            assert_eq!(finish_res, EndpointResult::Ok);
        });

        // setup client
        let client_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let mut ep = endpoint_default();
            let bind_res = endpoint_bind(&config_client, 0, &mut ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            // wait for addr from server
            let node_addr = r.recv().unwrap();

            println!("[c] dialing");
            // connect to server
            let mut conn = connection_default();
            let connect_res = endpoint_connect(&ep, alpn.as_ref(), node_addr, &mut conn);
            assert_eq!(connect_res, EndpointResult::Ok);

            println!("[c] accepting uni");
            let mut recv_stream = recv_stream_default();
            let open_res = connection_accept_uni(&conn, &mut recv_stream);
            assert_eq!(open_res, EndpointResult::Ok);

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
        let mut config_server = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_server, alpn.as_ref().into());

        let mut config_client = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_client, alpn.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();
        let (server_s, server_r) = std::sync::mpsc::channel();

        // setup server
        let alpn_s = alpn.clone();
        let server_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let mut ep = endpoint_default();
            let bind_res = endpoint_bind(&config_server, 0, &mut ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            let mut node_addr = node_addr_default();
            let res = endpoint_my_addr(&ep, &mut node_addr);
            assert_eq!(res, EndpointResult::Ok);

            s.send(node_addr).unwrap();

            // accept connection
            println!("[s] accepting conn");
            let mut conn = connection_default();
            let accept_res = endpoint_accept(&ep, alpn_s.as_ref(), &mut conn);
            assert_eq!(accept_res, EndpointResult::Ok);

            println!("[s] reading");

            let mut recv_buffer = rust_buffer_alloc(1024);
            let read_res = connection_read_datagram(&conn, &mut recv_buffer);
            assert_eq!(read_res, EndpointResult::Ok);
            assert_eq!(std::str::from_utf8(&recv_buffer).unwrap(), "hello world");
            server_s.send(()).unwrap();
        });

        // setup client
        let client_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let mut ep = endpoint_default();
            let bind_res = endpoint_bind(&config_client, 0, &mut ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            // wait for addr from server
            let node_addr = r.recv().unwrap();

            println!("[c] dialing");
            // connect to server
            let mut conn = connection_default();
            let connect_res = endpoint_connect(&ep, alpn.as_ref(), node_addr, &mut conn);
            assert_eq!(connect_res, EndpointResult::Ok);

            println!("[c] sending");
            let max_datagram = connection_max_datagram_size(&conn);
            assert!(max_datagram > 0);
            dbg!(max_datagram);
            let send_res = connection_write_datagram(&mut conn, b"hello world"[..].into());
            assert_eq!(send_res, EndpointResult::Ok);

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
        let mut config_server = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_server, alpn.as_ref().into());

        let mut config_client = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_client, alpn.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();
        let (client_s, client_r) = std::sync::mpsc::channel();

        // setup server
        let alpn_s = alpn.clone();
        let server_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let mut ep = endpoint_default();
            let bind_res = endpoint_bind(&config_server, 0, &mut ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            let mut node_addr = node_addr_default();
            let res = endpoint_my_addr(&ep, &mut node_addr);
            assert_eq!(res, EndpointResult::Ok);

            s.send(node_addr).unwrap();

            // accept connection
            println!("[s] accepting conn");
            let mut conn = connection_default();
            let res = endpoint_accept(&ep, alpn_s.as_ref(), &mut conn);
            assert_eq!(res, EndpointResult::Ok);

            let mut send_stream = send_stream_default();
            let mut recv_stream = recv_stream_default();
            let accept_res = connection_accept_bi(&conn, &mut send_stream, &mut recv_stream);
            assert_eq!(accept_res, EndpointResult::Ok);

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
            assert_eq!(send_res, EndpointResult::Ok);

            let res = send_stream_finish(send_stream);
            assert_eq!(res, EndpointResult::Ok);
            client_r.recv().unwrap();
        });

        // setup client
        let client_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let mut ep = endpoint_default();
            let bind_res = endpoint_bind(&config_client, 0, &mut ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            // wait for addr from server
            let node_addr = r.recv().unwrap();

            println!("[c] dialing");
            // connect to server
            let mut conn = connection_default();
            let connect_res = endpoint_connect(&ep, alpn.as_ref(), node_addr, &mut conn);
            assert_eq!(connect_res, EndpointResult::Ok);

            let mut send_stream = send_stream_default();
            let mut recv_stream = recv_stream_default();
            let open_res = connection_open_bi(&conn, &mut send_stream, &mut recv_stream);
            assert_eq!(open_res, EndpointResult::Ok);

            println!("[c] sending");
            let send_res = send_stream_write(&mut send_stream, b"hello world"[..].into());
            assert_eq!(send_res, EndpointResult::Ok);

            println!("[c] reading");

            let mut recv_buffer = vec![0u8; 1024];
            let read_res = recv_stream_read(&mut recv_stream, (&mut recv_buffer[..]).into());
            assert!(read_res > 0);
            assert_eq!(
                std::str::from_utf8(&recv_buffer[..read_res as usize]).unwrap(),
                "hello client"
            );

            let finish_res = send_stream_finish(send_stream);
            assert_eq!(finish_res, EndpointResult::Ok);
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
        let mut config_server = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_server, alpn1.as_ref().into());
        endpoint_config_add_alpn(&mut config_server, alpn2.as_ref().into());

        let mut config_client = endpoint_config_default();
        endpoint_config_add_alpn(&mut config_client, alpn1.as_ref().into());
        endpoint_config_add_alpn(&mut config_client, alpn2.as_ref().into());

        let (s, r) = std::sync::mpsc::channel();
        let (client1_s, client1_r) = std::sync::mpsc::channel();
        let (client2_s, client2_r) = std::sync::mpsc::channel();

        // setup server
        let alpn1_s = alpn1.clone();
        let alpn2_s = alpn2.clone();
        let server_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let ep = endpoint_default();
            let bind_res = endpoint_bind(&config_server, 0, &ep);
            assert_eq!(bind_res, EndpointResult::Ok);

            let mut node_addr = node_addr_default();
            let res = endpoint_my_addr(&ep, &mut node_addr);
            assert_eq!(res, EndpointResult::Ok);

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
                    let res = endpoint_accept_any(&ep, &mut alpn, &mut conn);
                    assert_eq!(res, EndpointResult::Ok);

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
                    assert_eq!(accept_res, EndpointResult::Ok);

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
                    assert_eq!(send_res, EndpointResult::Ok);

                    let res = send_stream_finish(send_stream);
                    assert_eq!(res, EndpointResult::Ok);
                    client_r.recv().unwrap();
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }
        });

        // setup client
        let client_thread = std::thread::spawn(move || {
            // create iroh endpoint and bind
            let ep = endpoint_default();
            let bind_res = endpoint_bind(&config_client, 0, &ep);
            assert_eq!(bind_res, EndpointResult::Ok);

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
                    let connect_res = endpoint_connect(&ep, alpn.as_ref(), node_addr, &mut conn);
                    assert_eq!(connect_res, EndpointResult::Ok);

                    let mut send_stream = send_stream_default();
                    let mut recv_stream = recv_stream_default();
                    let open_res = connection_open_bi(&conn, &mut send_stream, &mut recv_stream);
                    assert_eq!(open_res, EndpointResult::Ok);

                    println!("[c][{i}] sending");
                    let send_res = send_stream_write(
                        &mut send_stream,
                        format!("hello world {i}").as_bytes().into(),
                    );
                    assert_eq!(send_res, EndpointResult::Ok);

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
                    assert_eq!(finish_res, EndpointResult::Ok);
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