/*! \file */
/*******************************************
 *                                         *
 *  File auto-generated by `::safer_ffi`.  *
 *                                         *
 *  Do not manually edit this file.        *
 *                                         *
 *******************************************/

#ifndef __RUST_IROH_C_FFI__
#define __RUST_IROH_C_FFI__
#ifdef __cplusplus
extern "C" {
#endif

/** \brief
 *  An established connection.
 */
typedef struct Connection Connection_t;

/** \brief
 *  A stream that can only be used to send data
 */
typedef struct SendStream SendStream_t;

/** \brief
 *  A stream that can only be used to receive data.
 */
typedef struct RecvStream RecvStream_t;


#include <stddef.h>
#include <stdint.h>

/** \brief
 *  Result of dealing with a iroh endpoint.
 */
/** \remark Has the same ABI as `uint8_t` **/
#ifdef DOXYGEN
typedef
#endif
enum EndpointResult {
    /** \brief
     *  Everything is ok
     */
    ENDPOINT_RESULT_OK = 0,
    /** \brief
     *  Failed to bind.
     */
    ENDPOINT_RESULT_BIND_ERROR,
    /** \brief
     *  Failed to accept a connection.
     */
    ENDPOINT_RESULT_ACCEPT_FAILED,
    /** \brief
     *  Failed to accept a uni directional stream,
     */
    ENDPOINT_RESULT_ACCEPT_UNI_FAILED,
    /** \brief
     *  Failed to accept a bi directional stream,
     */
    ENDPOINT_RESULT_ACCEPT_BI_FAILED,
    /** \brief
     *  Failed to connect and establish a uni directional stream.
     */
    ENDPOINT_RESULT_CONNECT_UNI_ERROR,
    /** \brief
     *  Failed to connect and establish a bi directional stream.
     */
    ENDPOINT_RESULT_CONNECT_BI_ERROR,
    /** \brief
     *  Failed to connect.
     */
    ENDPOINT_RESULT_CONNECT_ERROR,
    /** \brief
     *  Unable to retrive node addr.
     */
    ENDPOINT_RESULT_ADDR_ERROR,
    /** \brief
     *  Error while sending data.
     */
    ENDPOINT_RESULT_SEND_ERROR,
    /** \brief
     *  Error while reading data.
     */
    ENDPOINT_RESULT_READ_ERROR,
    /** \brief
     *  Timeout elapsed.
     */
    ENDPOINT_RESULT_TIMEOUT,
    /** \brief
     *  Error while closing.
     */
    ENDPOINT_RESULT_CLOSE_ERROR,
    /** \brief
     *  Failed to accept an incoming connection.
     *
     *  This occurs before the handshake is even attempted.
     *
     *  Likely not caused by the application or remote. The QUIC connection listens on a normal UDP socket and any reachable network endpoint can send datagrams to it, solicited or not.
     *
     *  It is common to simply log this error and move on.
     */
    ENDPOINT_RESULT_INCOMING_ERROR,
    /** \brief
     *  Unable to find connection for the given `NodeId`
     */
    ENDPOINT_RESULT_CONNECTION_TYPE_ERROR,
}
#ifndef DOXYGEN
; typedef uint8_t
#endif
EndpointResult_t;

/** \brief
 *  Accept a bi directional stream on this endpoint.
 *
 *  Blocks the current thread.
 */
EndpointResult_t
connection_accept_bi (
    Connection_t * const * conn,
    SendStream_t * * send,
    RecvStream_t * * recv);

/** \brief
 *  Accepts a uni directional stream on this connection.
 *
 *  Blocks the current thread.
 */
EndpointResult_t
connection_accept_uni (
    Connection_t * const * conn,
    RecvStream_t * * out);

/** \brief
 *  Close a connection
 *
 *  Consumes the connection, no need to free it afterwards.
 */
void
connection_close (
    Connection_t * conn);

/** \brief
 *  Wait for the connection to be closed.
 *
 *  Blocks the current thread.
 *
 *  Consumes the connection, no need to free it afterwards.
 */
EndpointResult_t
connection_closed (
    Connection_t * conn);

/** \brief
 *  Result must be freed using `connection_free`.
 */
Connection_t *
connection_default (void);

/** \brief
 *  Frees the connection.
 */
void
connection_free (
    Connection_t * conn);

/** \brief
 *  Returns the maximum datagram size. `0` if it is not supported.
 */
size_t
connection_max_datagram_size (
    Connection_t * const * connection);

/** \brief
 *  Establish a bi directional connection.
 *
 *  Blocks the current thread until the connection is established.
 */
EndpointResult_t
connection_open_bi (
    Connection_t * const * conn,
    SendStream_t * * send,
    RecvStream_t * * recv);

/** \brief
 *  Establish a uni directional connection.
 *
 *  Blocks the current thread until the connection is established.
 */
EndpointResult_t
connection_open_uni (
    Connection_t * const * conn,
    SendStream_t * * out);

/** \brief
 *  Returns the ratio of lost packets to sent packets.
 */
double
connection_packet_loss (
    Connection_t * const * conn);

/** \brief
 *  Same as [`Vec<T>`][`rust::Vec`], but with guaranteed `#[repr(C)]` layout
 */
typedef struct Vec_uint8 {
    /** <No documentation available> */
    uint8_t * ptr;

    /** <No documentation available> */
    size_t len;

    /** <No documentation available> */
    size_t cap;
} Vec_uint8_t;

/** \brief
 *  Reads a datgram.
 *
 *  Data must not be larger than the available `max_datagram` size.
 *
 *  Blocks the current thread until a datagram is received.
 */
EndpointResult_t
connection_read_datagram (
    Connection_t * const * connection,
    Vec_uint8_t * data);

/** \brief
 *  Reads a datgram, with timeout.
 *
 *  Will block at most `timeout` milliseconds.
 *
 *  Data received will not be larger than the available `max_datagram` size.
 *
 *  Blocks the current thread until a datagram is received or the timeout is expired.
 */
EndpointResult_t
connection_read_datagram_timeout (
    Connection_t * const * connection,
    Vec_uint8_t * data,
    uint64_t timeout_ms);

/** \brief
 *  Estimated roundtrip time for the current connection in milli seconds.
 */
uint64_t
connection_rtt (
    Connection_t * const * conn);

/** \brief
 *  `&'lt [T]` but with a guaranteed `#[repr(C)]` layout.
 *
 *  # C layout (for some given type T)
 *
 *  ```c
 *  typedef struct {
 *  // Cannot be NULL
 *  T * ptr;
 *  size_t len;
 *  } slice_T;
 *  ```
 *
 *  # Nullable pointer?
 *
 *  If you want to support the above typedef, but where the `ptr` field is
 *  allowed to be `NULL` (with the contents of `len` then being undefined)
 *  use the `Option< slice_ptr<_> >` type.
 */
typedef struct slice_ref_uint8 {
    /** \brief
     *  Pointer to the first element (if any).
     */
    uint8_t const * ptr;

    /** \brief
     *  Element count
     */
    size_t len;
} slice_ref_uint8_t;

/** \brief
 *  Send a single datgram (unreliably).
 *
 *  Data must not be larger than the available `max_datagram` size.
 */
EndpointResult_t
connection_write_datagram (
    Connection_t * const * connection,
    slice_ref_uint8_t data);

/** \brief
 *  An endpoint that leverages a quic endpoint, backed by a iroh socket.
 */
typedef struct Endpoint Endpoint_t;

/** \brief
 *  Accept a new connection on this endpoint.
 *
 *  Blocks the current thread until a connection is established.
 *
 *  An [`EndpointResult::IncomingError`] occurring here is likely not caused by the application or remote. The QUIC connection listens on a normal UDP socket and any reachable network endpoint can send datagrams to it, solicited or not.
 *  It is not considered fatal and is common to simply log and ignore.
 */
EndpointResult_t
endpoint_accept (
    Endpoint_t * const * ep,
    slice_ref_uint8_t expected_alpn,
    Connection_t * const * out);

/** \brief
 *  Accept a new connection on this endpoint.
 *
 *  Does not prespecify the ALPN, and but rather returns it.
 *
 *  Blocks the current thread until a connection is established.
 *
 *  An [`EndpointResult::IncomingError`] occurring here is likely not caused by the application or remote. The QUIC connection listens on a normal UDP socket and any reachable network endpoint can send datagrams to it, solicited or not.
 *  It is not considered fatal and is common to simply log and ignore.
 */
EndpointResult_t
endpoint_accept_any (
    Endpoint_t * const * ep,
    Vec_uint8_t * alpn_out,
    Connection_t * const * out);

/** \brief
 *  Accept a new connection on this endpoint.
 *
 *  Does not prespecify the ALPN, and but rather returns it.
 *
 *  Does not block, the provided callback will be called the next time a new connection is accepted or
 *  when an error occurs.
 *  `ctx` is passed along to the callback, to allow passing context, it must be thread safe as the callback is
 *  called from another thread.
 *
 *  An [`EndpointResult::IncomingError`] occurring here is likely not caused by the application or remote. The QUIC connection listens on a normal UDP socket and any reachable network endpoint can send datagrams to it, solicited or not.
 *  It is not considered fatal and is common to simply log and ignore.
 */
void
endpoint_accept_any_cb (
    Endpoint_t * ep,
    void const * ctx,
    void (*cb)(void const *, EndpointResult_t, Vec_uint8_t, Connection_t *));

/** \brief
 *  The options to configure relay.
 */
/** \remark Has the same ABI as `uint8_t` **/
#ifdef DOXYGEN
typedef
#endif
enum RelayMode {
    /** \brief
     *  Relay mode is entirely disabled
     */
    RELAY_MODE_DISABLED,
    /** \brief
     *  Default relay map is used.
     */
    RELAY_MODE_DEFAULT,
}
#ifndef DOXYGEN
; typedef uint8_t
#endif
RelayMode_t;

/** \brief
 *  Configuration for Discovery
 */
/** \remark Has the same ABI as `uint8_t` **/
#ifdef DOXYGEN
typedef
#endif
enum DiscoveryConfig {
    /** \brief
     *  Use no node discovery mechanism. The default.
     */
    DISCOVERY_CONFIG_NONE,
    /** \brief
     *  DNS Discovery service.
     *
     *  Allows for global node discovery. Requires access to the internet to work properly.
     */
    DISCOVERY_CONFIG_D_N_S,
    /** \brief
     *  Mdns Discovery service.
     *
     *  Allows for local node discovery. Discovers other iroh nodes in your local network
     *  If your local network does not have multicast abilities, creating a local swarm discovery service will log an error, but fail silently.
     */
    DISCOVERY_CONFIG_MDNS,
    /** \brief
     *  Use both DNS and Mdns Discovery
     *  If your local network does not have multicast abilities, creating a local swarm discovery service will log an error, but fail silently.
     */
    DISCOVERY_CONFIG_ALL,
}
#ifndef DOXYGEN
; typedef uint8_t
#endif
DiscoveryConfig_t;

/** \brief
 *  Same as [`Vec<T>`][`rust::Vec`], but with guaranteed `#[repr(C)]` layout
 */
typedef struct Vec_Vec_uint8 {
    /** <No documentation available> */
    Vec_uint8_t * ptr;

    /** <No documentation available> */
    size_t len;

    /** <No documentation available> */
    size_t cap;
} Vec_Vec_uint8_t;

/** \brief
 *  A secret key.
 */
typedef struct SecretKey SecretKey_t;

/** \brief
 *  Configuration options for the Endpoint.
 */
typedef struct EndpointConfig {
    /** <No documentation available> */
    RelayMode_t relay_mode;

    /** <No documentation available> */
    DiscoveryConfig_t discovery_cfg;

    /** <No documentation available> */
    Vec_Vec_uint8_t alpn_protocols;

    /** <No documentation available> */
    SecretKey_t * secret_key;
} EndpointConfig_t;

/** \brief
 *  Represents an IPv4 address, including a port number.
 */
typedef struct SocketAddrV4 SocketAddrV4_t;

/** \brief
 *  Represents an IPv6 address, including a port number.
 */
typedef struct SocketAddrV6 SocketAddrV6_t;

/** \brief
 *  Attempts to bind the endpoint to the provided IPv4 and IPv6 address.
 *
 *  If the selected port is already in use, a random port will be used.
 *
 *  Blocks the current thread.
 */
EndpointResult_t
endpoint_bind (
    EndpointConfig_t const * config,
    SocketAddrV4_t * ipv4_addr,
    SocketAddrV6_t * ipv6_addr,
    Endpoint_t * const * out);

/** \brief
 *  Closes the endpoint.
 *
 *  It blocks all incoming connections and then waits for all current connections
 *  to close gracefully, before shutting down the endpoint.
 *
 *  Consumes the endpoint, no need to free it afterwards.
 */
void
endpoint_close (
    Endpoint_t * ep);

/** \brief
 *  Add the given ALPN to the list of accepted ALPNs.
 */
void
endpoint_config_add_alpn (
    EndpointConfig_t * config,
    slice_ref_uint8_t alpn);

/** \brief
 *  Sets the given secret key to use.
 */
void
endpoint_config_add_secret_key (
    EndpointConfig_t * config,
    SecretKey_t * secret_key);

/** \brief
 *  Generate a default endpoint configuration.
 *
 *  Must be freed using `endpoint_config_free`.
 */
EndpointConfig_t
endpoint_config_default (void);

/** \brief
 *  Frees the iroh endpoint config.
 */
void
endpoint_config_free (
    EndpointConfig_t config);

typedef struct {
    uint8_t idx[32];
} uint8_32_array_t;

/** \brief
 *  A public key.
 */
typedef struct PublicKey {
    /** <No documentation available> */
    uint8_32_array_t key;
} PublicKey_t;

/** <No documentation available> */
/** \remark Has the same ABI as `uint8_t` **/
#ifdef DOXYGEN
typedef
#endif
enum ConnectionType {
    /** \brief
     *  Direct UDP connection
     */
    CONNECTION_TYPE_DIRECT = 0,
    /** \brief
     *  Relay connection over relay
     */
    CONNECTION_TYPE_RELAY,
    /** \brief
     *  Both a UDP and a relay connection are used.
     *
     *  This is the case if we do have a UDP address, but are missing a recent confirmation that
     *  the address works.
     */
    CONNECTION_TYPE_MIXED,
    /** \brief
     *  We have no verified connection to this PublicKey
     */
    CONNECTION_TYPE_NONE,
}
#ifndef DOXYGEN
; typedef uint8_t
#endif
ConnectionType_t;

/** \brief
 *  Run a callback each time the [`ConnectionType`] to that peer has changed.
 *
 *  Does not block. This will run until the connection has closed.
 *
 *  `ctx` is passed along to the callback, to allow passing context, it must be thread safe as the callback is
 *  called from another thread.
 */
void
endpoint_conn_type_cb (
    Endpoint_t * ep,
    void const * ctx,
    PublicKey_t const * node_id,
    void (*cb)(void const *, EndpointResult_t, ConnectionType_t));

/** \brief
 *  Represents a valid URL.
 */
typedef struct Url Url_t;

/** \brief
 *  Represents an IPv4 or IPv6 address, including a port number.
 */
typedef struct SocketAddr SocketAddr_t;

/** \brief
 *  Same as [`Vec<T>`][`rust::Vec`], but with guaranteed `#[repr(C)]` layout
 */
typedef struct Vec_SocketAddr_ptr {
    /** <No documentation available> */
    SocketAddr_t * * ptr;

    /** <No documentation available> */
    size_t len;

    /** <No documentation available> */
    size_t cap;
} Vec_SocketAddr_ptr_t;

/** \brief
 *  A peer and it's addressing information.
 */
typedef struct NodeAddr {
    /** \brief
     *  The node's public key.
     */
    PublicKey_t node_id;

    /** \brief
     *  The peer's home RELAY url.
     */
    Url_t * relay_url;

    /** \brief
     *  Socket addresses where the peer might be reached directly.
     */
    Vec_SocketAddr_ptr_t direct_addresses;
} NodeAddr_t;

/** \brief
 *  Connects to the given node.
 *
 *  Blocks until the connection is established.
 */
EndpointResult_t
endpoint_connect (
    Endpoint_t * const * ep,
    slice_ref_uint8_t alpn,
    NodeAddr_t node_addr,
    Connection_t * const * out);

/** \brief
 *  Generate a default endpoint.
 *
 *  Must be freed using `endpoint_free`.
 */
Endpoint_t *
endpoint_default (void);

/** \brief
 *  Frees the iroh endpoint.
 */
void
endpoint_free (
    Endpoint_t * ep);

/** \brief
 *  Get the home relay of this iroh endpoint.
 */
EndpointResult_t
endpoint_home_relay (
    Endpoint_t * const * ep,
    Url_t * out);

/** \brief
 *  Let the endpoint know that the underlying network conditions might have changed.
 *
 *  This really only needs to be called on android,
 *  Ref https://developer.android.com/training/monitoring-device-state/connectivity-status-type
 */
void
endpoint_network_change (
    Endpoint_t * const * ep);

/** \brief
 *  Get the node dialing information of this iroh endpoint.
 */
EndpointResult_t
endpoint_node_addr (
    Endpoint_t * const * ep,
    NodeAddr_t * out);

/** \brief
 *  Enables tracing for iroh.
 *
 *  Log level can be controlled using the env variable `IROH_C_LOG`.
 */
void
iroh_enable_tracing (void);

/** \brief
 *  Add the given direct addresses to the peer's addr info.
 */
void
node_addr_add_direct_address (
    NodeAddr_t * node_addr,
    SocketAddr_t * address);

/** \brief
 *  Add a relay url to the peer's addr info.
 */
void
node_addr_add_relay_url (
    NodeAddr_t * addr,
    Url_t * relay_url);

/** \brief
 *  Formats the given node addr as a string.
 *
 *  Result must be freed with `rust_free_string`
 */
char *
node_addr_as_str (
    NodeAddr_t const * addr);

/** \brief
 *  Create a an empty (invalid) addr with no details.
 *
 *  Must be freed using `node_addr_free`.
 */
NodeAddr_t
node_addr_default (void);

/** \brief
 *  Get the nth direct addresses of this peer.
 *
 *  Panics if i is larger than the available addrs.
 */
SocketAddr_t const *
node_addr_direct_addresses_nth (
    NodeAddr_t const * addr,
    size_t i);

/** \brief
 *  Free the node addr.
 */
void
node_addr_free (
    NodeAddr_t node_addr);

/** <No documentation available> */
/** \remark Has the same ABI as `uint8_t` **/
#ifdef DOXYGEN
typedef
#endif
enum AddrResult {
    /** \brief
     *  Everything is ok.
     */
    ADDR_RESULT_OK = 0,
    /** \brief
     *  Url was invalid.
     */
    ADDR_RESULT_INVALID_URL,
    /** \brief
     *  SocketAddr was invalid.
     */
    ADDR_RESULT_INVALID_SOCKET_ADDR,
    /** \brief
     *  The node addr was invalid.
     */
    ADDR_RESULT_INVALID_NODE_ADDR,
}
#ifndef DOXYGEN
; typedef uint8_t
#endif
AddrResult_t;

/** \brief
 *  Parses the full node addr string representation.
 */
AddrResult_t
node_addr_from_string (
    char const * input,
    NodeAddr_t * out);

/** \brief
 *  Create a new addr with no details.
 *
 *  Must be freed using `node_addr_free`.
 */
NodeAddr_t
node_addr_new (
    PublicKey_t node_id);

/** \brief
 *  Get the relay url of this peer.
 */
Url_t * const *
node_addr_relay_url (
    NodeAddr_t const * addr);

/** \brief
 *  Returns the public key as a base32 string.
 *
 *  Result must be freed using `rust_free_string`
 */
char *
public_key_as_base32 (
    PublicKey_t const * key);

/** \brief
 *  Generate a default (invalid) public key.
 *
 *  Result must be freed using `public_key_free`.
 */
PublicKey_t
public_key_default (void);

/** \brief
 *  Free the passed in key.
 */
void
public_key_free (
    PublicKey_t _key);

/** \brief
 *  Result of handling key material.
 */
/** \remark Has the same ABI as `uint8_t` **/
#ifdef DOXYGEN
typedef
#endif
enum KeyResult {
    /** \brief
     *  Everything is ok.
     */
    KEY_RESULT_OK = 0,
    /** \brief
     *  Invalid public key material.
     */
    KEY_RESULT_INVALID_PUBLIC_KEY,
    /** \brief
     *  Invalid secret key material.
     */
    KEY_RESULT_INVALID_SECRET_KEY,
}
#ifndef DOXYGEN
; typedef uint8_t
#endif
KeyResult_t;

/** \brief
 *  Parses the public key from a base32 string.
 */
KeyResult_t
public_key_from_base32 (
    char const * raw_key,
    PublicKey_t * out);

/** \brief
 *  Must be freed using `recv_stream_free`.
 */
RecvStream_t *
recv_stream_default (void);

/** \brief
 *  Free the recv stream.
 *
 *  Implicitly calls `stop(0)` on the connection.
 */
void
recv_stream_free (
    RecvStream_t * stream);

/** \brief
 *  Unique stream id.
 */
uint64_t
recv_stream_id (
    RecvStream_t * const * stream);

/** \brief
 *  `&'lt mut [T]` but with a guaranteed `#[repr(C)]` layout.
 *
 *  # C layout (for some given type T)
 *
 *  ```c
 *  typedef struct {
 *  // Cannot be NULL
 *  T * ptr;
 *  size_t len;
 *  } slice_T;
 *  ```
 *
 *  # Nullable pointer?
 *
 *  If you want to support the above typedef, but where the `ptr` field is
 *  allowed to be `NULL` (with the contents of `len` then being undefined)
 *  use the `Option< slice_ptr<_> >` type.
 */
typedef struct slice_mut_uint8 {
    /** \brief
     *  Pointer to the first element (if any).
     */
    uint8_t * ptr;

    /** \brief
     *  Element count
     */
    size_t len;
} slice_mut_uint8_t;

/** \brief
 *  Receive data on this stream.
 *
 *  Blocks the current thread.
 *
 *  Returns how many bytes were read. Returns `-1` if an error occured.
 */
int64_t
recv_stream_read (
    RecvStream_t * * stream,
    slice_mut_uint8_t data);

/** \brief
 *  Receive data on this stream and return with an error if reading exceeds the
 *  given timeout.
 *
 *  Blocks the current thread.
 *
 *  On success, returns how many bytes were read in the `bytes_read` parameter.
 */
int64_t
recv_stream_read_timeout (
    RecvStream_t * * stream,
    slice_mut_uint8_t data,
    uint64_t timeout_ms);

/** \brief
 *  Receive data on this stream.
 *
 *  Size limit specifies how much data at most is read.
 *
 *  Blocks the current thread, until either the full stream has been read, or
 *  the timeout has expired.
 */
EndpointResult_t
recv_stream_read_to_end_timeout (
    RecvStream_t * * stream,
    Vec_uint8_t * data,
    size_t size_limit,
    uint64_t timeout_ms);

/** \brief
 *  Allocates a buffer managed by rust, given the initial size.
 */
Vec_uint8_t
rust_buffer_alloc (
    size_t size);

/** \brief
 *  Frees the rust buffer.
 */
void
rust_buffer_free (
    Vec_uint8_t buf);

/** \brief
 *  Returns the length of the buffer.
 */
size_t
rust_buffer_len (
    Vec_uint8_t const * buf);

/** \brief
 *  Frees a Rust-allocated string.
 */
void
rust_free_string (
    char * string);

/** \brief
 *  Returns the secret key as a base32 string.
 *
 *  Result must be freed using `rust_free_string`
 */
char *
secret_key_as_base32 (
    SecretKey_t const * key);

/** \brief
 *  Generate a default secret key.
 *
 *  Result must be freed using `secret_key_free`.
 */
SecretKey_t *
secret_key_default (void);

/** \brief
 *  Free the passed in key.
 */
void
secret_key_free (
    SecretKey_t * key);

/** \brief
 *  Parses the secret key from a base32 string.
 */
KeyResult_t
secret_key_from_base32 (
    char const * raw_key,
    SecretKey_t * * out);

/** \brief
 *  Generates a new key with default OS randomness.
 *
 *  Result must be freed using `secret_key_free`
 */
SecretKey_t *
secret_key_generate (void);

/** \brief
 *  The public key for this secret key.
 *
 *  Result must be freed using `public_key_free`
 */
PublicKey_t
secret_key_public (
    SecretKey_t const * key);

/** \brief
 *  Must be freed using `send_stream_free`.
 */
SendStream_t *
send_stream_default (void);

/** \brief
 *  Finish the sending on this stream.
 *
 *  Consumes the send stream, no need to free it afterwards.
 */
EndpointResult_t
send_stream_finish (
    SendStream_t * stream);

/** \brief
 *  Frees the send stream.
 */
void
send_stream_free (
    SendStream_t * stream);

/** \brief
 *  Unique stream id.
 */
uint64_t
send_stream_id (
    SendStream_t * const * stream);

/** \brief
 *  Send data on the stream.
 *
 *  Blocks the current thread.
 */
EndpointResult_t
send_stream_write (
    SendStream_t * * stream,
    slice_ref_uint8_t data);

/** \brief
 *  Send data on the stream, returning an error if the data was not written
 *  before the given timeout.
 *
 *  Blocks the current thread.
 */
EndpointResult_t
send_stream_write_timeout (
    SendStream_t * * stream,
    slice_ref_uint8_t data,
    uint64_t timeout_ms);

/** \brief
 *  Formats the given socket addr as a string
 *
 *  Result must be freed with `rust_free_string`
 */
char *
socket_addr_as_str (
    SocketAddr_t const * addr);

/** <No documentation available> */
SocketAddr_t *
socket_addr_default (void);

/** <No documentation available> */
void
socket_addr_free (
    SocketAddr_t * addr);

/** \brief
 *  Try to parse a url from a string.
 */
AddrResult_t
socket_addr_from_string (
    char const * input,
    SocketAddr_t * * out);

/** \brief
 *  Formats the given socket addr as a string
 *
 *  Result must be freed with `rust_free_string`
 */
char *
socket_addr_v4_as_str (
    SocketAddrV4_t const * addr);

/** <No documentation available> */
SocketAddrV4_t *
socket_addr_v4_default (void);

/** <No documentation available> */
void
socket_addr_v4_free (
    SocketAddrV4_t * addr);

/** \brief
 *  Try to parse a url from a string.
 */
AddrResult_t
socket_addr_v4_from_string (
    char const * input,
    SocketAddrV4_t * * out);

/** \brief
 *  Formats the given socket addr as a string
 *
 *  Result must be freed with `rust_free_string`
 */
char *
socket_addr_v6_as_str (
    SocketAddrV6_t const * addr);

/** <No documentation available> */
SocketAddrV6_t *
socket_addr_v6_default (void);

/** <No documentation available> */
void
socket_addr_v6_free (
    SocketAddrV6_t * addr);

/** \brief
 *  Try to parse a url from a string.
 */
AddrResult_t
socket_addr_v6_from_string (
    char const * input,
    SocketAddrV6_t * * out);

/** \brief
 *  Formats the given url as a string
 *
 *  Result must be freed with `rust_free_string`
 */
char *
url_as_str (
    Url_t const * url);

/** \brief
 *  Creates an initialized but invalid Url.
 */
Url_t *
url_default (void);

/** \brief
 *  Try to parse a url from a string.
 */
AddrResult_t
url_from_string (
    char const * input,
    Url_t * * out);


#ifdef __cplusplus
} /* extern \"C\" */
#endif

#endif /* __RUST_IROH_C_FFI__ */
