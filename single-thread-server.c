#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "irohnet.h"
Connection_t *conn1;
Connection_t *conn2;

int main(int argc, char const *const argv[]) {
  iroh_enable_tracing();

  RecvStream_t *recv_stream = recv_stream_default();
  RecvStream_t *recv_stream2 = recv_stream_default();
  SendStream_t *send_stream = send_stream_default();
  SendStream_t *send_stream2 = send_stream_default();
  int accepted = 0;
  char alpn_str1[] = "/cool/alpn/1";
  char alpn_str2[] = "/cool/alpn/2";

  // Assuming server and client specific parameters are initialized here...

  // Server thread 1
  slice_ref_uint8_t alpn1, alpn2;
  alpn1.ptr = (uint8_t *)&alpn_str1[0];
  alpn1.len = strlen(alpn_str1);
  alpn2.ptr = (uint8_t *)&alpn_str2[0];
  alpn2.len = strlen(alpn_str2);
  MagicEndpointConfig_t config = magic_endpoint_config_default();
  magic_endpoint_config_add_alpn(&config, alpn1);
  magic_endpoint_config_add_alpn(&config, alpn2);

  MagicEndpoint_t *ep = magic_endpoint_default();
  int bind_res = magic_endpoint_bind(&config, 0, &ep);
  if (bind_res != 0) {
    fprintf(stderr, "failed to bind server\n");
    return -1;
  }

  // Print details
  NodeAddr_t my_addr = node_addr_default();
  int addr_res = magic_endpoint_my_addr(&ep, &my_addr);
  if (addr_res != 0) {
    fprintf(stderr, "faile to get my address");
    return -1;
  }
  char *node_id_str = public_key_as_base32(&my_addr.node_id);
  char *relay_url_str = url_as_str(my_addr.relay_url);

  printf("Listening on:\nNode Id: %s\nRelay: %s\nAddrs:\n", node_id_str,
         relay_url_str);
  printf("Node Address is \n%s\n", node_addr_as_str(&my_addr));

  // iterate over the direct addresses
  for (int i = 0; i < my_addr.direct_addresses.len; i++) {
    SocketAddr_t const *addr = node_addr_direct_addresses_nth(&my_addr, i);
    char *socket_str = socket_addr_as_str(addr);
    printf("  - %s\n", socket_str);
    rust_free_string(socket_str);
  }
  printf("\n");
  fflush(stdout);
  conn1 = connection_default();
  conn2 = connection_default();
  while (accepted < 2) {
    Vec_uint8_t alpn_slice_out = rust_buffer_alloc(0);
    // int res = magic_endpoint_accept(&ep, alpn_slice_control, &conn);

    int res;
    if (accepted == 0)
      res = magic_endpoint_accept_any(&ep, &alpn_slice_out, &conn1);
    else
      res = magic_endpoint_accept_any(&ep, &alpn_slice_out, &conn2);

    printf("Connection accepted with alpn %s \n", alpn_slice_out.ptr);

    if (res != 0) {
      printf("[Iroh] failed to accept connection");
      return 1;
    }
    rust_buffer_free(alpn_slice_out);
    accepted++;
  }
  printf("Accepting connection 1\n");
  int err = connection_accept_bi(&conn1, &send_stream, &recv_stream);
  if (err != 0) {
    fprintf(stderr, "failed to accept streams");
    return -1;
  }

  printf("reading to end\n");
  Vec_uint8_t recvBuffer = rust_buffer_alloc(0);
  err = recv_stream_read_to_end_timeout(&recv_stream, &recvBuffer, 1024, 5000);
  if (err == MAGIC_ENDPOINT_RESULT_TIMEOUT) {
    printf("Response timed out\n");
    return 1;
  } else if (err != 0) {
    printf("Failed to wait for response: %d\n", err);
    return 1;
  }

  char *data = "hello world from C - 1";
  slice_ref_uint8_t buffer;
  buffer.ptr = (uint8_t *)&data[0];
  buffer.len = strlen(data);

  err = send_stream_write(&send_stream, buffer);
  if (err != 0) {
    fprintf(stderr, "failed to write to stream");
    return -1;
  }
  send_stream_finish(send_stream);
  recv_stream_free(recv_stream);

  printf("Accepting connection 2\n");
  err = connection_accept_bi(&conn2, &send_stream2, &recv_stream2);
  if (err != 0) {
    fprintf(stderr, "failed to accept streams");
    return -1;
  }

  printf("reading to end\n");
  err = recv_stream_read_to_end_timeout(&recv_stream2, &recvBuffer, 1024, 5000);
  if (err == MAGIC_ENDPOINT_RESULT_TIMEOUT) {
    printf("Response timed out\n");
    return 1;
  } else if (err != 0) {
    printf("Failed to wait for response: %d\n", err);
    return 1;
  }

  char *data2 = "hello world from C - 2";
  buffer.ptr = (uint8_t *)&data2[0];
  buffer.len = strlen(data2);

  err = send_stream_write(&send_stream2, buffer);

  if (err != 0) {
    fprintf(stderr, "failed to write to stream");
    return -1;
  }
  send_stream_finish(send_stream2);
  recv_stream_free(recv_stream2);
  rust_buffer_free(recvBuffer);
  return 0;
}
