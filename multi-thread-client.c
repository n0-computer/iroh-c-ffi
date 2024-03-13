#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "irohnet.h"

int run_client(MagicEndpointConfig_t *config, slice_ref_uint8_t alpn_slice,
               char const *node_id_raw, char const *derp_url_raw,
               char const **addrs_raw, int addrs_len) {
  printf("Starting client...\n");

  // create node addr
  NodeAddr_t node_addr = node_addr_default();

  // char *nodeAddrToUse = node_id;
  int err = node_addr_from_string(strdup(node_id_raw), &node_addr);
  if (err != 0) {
    fprintf(stderr, "invalid node_addr '%s'\n", node_id_raw);
    return -1;
  }

  printf("binding magic endpoint\n");
  MagicEndpoint_t *ep = magic_endpoint_default();
  int bind_res = magic_endpoint_bind(config, 0, &ep);
  if (bind_res != 0) {
    fprintf(stderr, "failed to bind\n");
    return -1;
  }

  // connect
  printf("connecting to %s\n", alpn_slice.ptr);
  Connection_t *conn = connection_default();
  int ret = magic_endpoint_connect(&ep, alpn_slice, node_addr, &conn);
  if (ret != 0) {
    printf("failed to connect to server\n");
    return -1;
  }

  RecvStream_t *recv_stream = recv_stream_default();
  SendStream_t *send_stream = send_stream_default();

  printf("opening bi stream\n");
  err = connection_open_bi(&conn, &send_stream, &recv_stream);
  if (err != 0) {
    printf("Failed to establish stream : %d\n", err);
    return 1;
  }

  printf("sending message\n");
  char *data2 = "hello world from client";
  slice_ref_uint8_t buffer;
  buffer.ptr = (uint8_t *)&data2[0];
  buffer.len = strlen(data2);
  err = send_stream_write(&send_stream, buffer);
  if (err != 0) {
    fprintf(stderr, "failed to write\n");
    return -1;
  }
  send_stream_finish(send_stream);

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

  printf("Received message: %s\n", recvBuffer.ptr);

  recv_stream_free(recv_stream);
  connection_free(conn);

  return 0;
}
// Define a structure to pass multiple parameters to the pthread functions
typedef struct {
  MagicEndpointConfig_t *config;
  slice_ref_uint8_t alpn_slice;
  MagicEndpoint_t *ep;
  bool json_output;     // For server
  const char *node_id;  // For client
  const char *derp_url; // For client
  const char **addrs;   // For client
  int addrs_len;        // For client
} ThreadParam;

// Wrapper function for the client
void *client_thread_func(void *arg) {
  ThreadParam *params = (ThreadParam *)arg;
  run_client(params->config, params->alpn_slice, params->node_id,
             params->derp_url, params->addrs, params->addrs_len);
  pthread_exit(NULL);
}

int main(int argc, char const *const argv[]) {
  iroh_enable_tracing();

  pthread_t client_threads[2];
  ThreadParam client_params[2];

  // Initialize parameters for each thread, including different ALPNs
  char alpn1[] = "/cool/alpn/1";
  char alpn2[] = "/cool/alpn/2";

  // Assuming server and client specific parameters are initialized here...

  // Server thread 1
  client_params[0].alpn_slice.ptr = (uint8_t *)&alpn1[0];
  client_params[0].alpn_slice.len = strlen(alpn1);
  client_params[0].json_output = false; // Or true, based on your requirement
  MagicEndpointConfig_t config = magic_endpoint_config_default();
  magic_endpoint_config_add_alpn(&config, client_params[0].alpn_slice);
  client_params[0].config = &config;

  // Server thread 2 with different ALPN
  client_params[1].alpn_slice.ptr = (uint8_t *)&alpn2[0];
  client_params[1].alpn_slice.len = strlen(alpn2);
  client_params[1].json_output = false; // Or true
  MagicEndpointConfig_t config2 = magic_endpoint_config_default();
  magic_endpoint_config_add_alpn(&config2, client_params[1].alpn_slice);
  client_params[1].config = &config2;

  if (argc < 1) {
    fprintf(stderr,
            "client must be supplied <node id> <derp-url> <addr1> .. <addrn>");
    return -1;
  }
  char const *nodeAddressStr = argv[1];

  client_params[0].node_id = strdup(nodeAddressStr);
  client_params[1].node_id = strdup(nodeAddressStr);
  pthread_create(&client_threads[0], NULL, client_thread_func,
                 (void *)&client_params[0]);
  pthread_create(&client_threads[1], NULL, client_thread_func,
                 (void *)&client_params[1]);
  pthread_join(client_threads[0], NULL);
  pthread_join(client_threads[1], NULL);

  return 0;
}
