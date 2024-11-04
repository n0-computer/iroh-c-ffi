/* Example program testing the api */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "irohnet.h"

int
run_server (EndpointConfig_t * config, slice_ref_uint8_t alpn_slice, bool json_output)
{
  if (json_output) {
    printf("{ \"type\": \"server\", \"status\": \"starting\" }\n");
  } else {
    printf("Starting server...\n");
  }

  // Bind
  Endpoint_t * ep = endpoint_default();
  int bind_res = endpoint_bind(config, NULL, NULL, &ep);
  if (bind_res != 0) {
    fprintf(stderr, "failed to bind server\n");
    return -1;
  }

  // Print details
  NodeAddr_t node_addr = node_addr_default();
  int addr_res = endpoint_node_addr(&ep, &node_addr);
  if (addr_res != 0) {
    fprintf(stderr, "failed to get my address");
    return -1;
  }
  char * node_id_str = public_key_as_base32(&node_addr.node_id);
  char * relay_url_str = url_as_str(node_addr.relay_url);
  if (json_output) {
    printf("{ \"type\": \"server\", \"status\": \"listening\", \"node_id\": \"%s\", \"relay\": \"%s\", \"addrs\": [", node_id_str, relay_url_str);
  } else {
    printf("Listening on:\nNode Id: %s\nRelay: %s\nAddrs:\n", node_id_str, relay_url_str);
  }

  // iterate over the direct addresses
  for (int i = 0; i < node_addr.direct_addresses.len; i++) {
    SocketAddr_t const * addr = node_addr_direct_addresses_nth(&node_addr, i);
    char * socket_str = socket_addr_as_str(addr);
    if (json_output) {
      printf("\"%s\"", socket_str);
      if (i < node_addr.direct_addresses.len - 1) {
        printf(", ");
      }
    } else {
      printf("  - %s\n", socket_str);
    }
    rust_free_string(socket_str);
  }
  if (json_output) {
    printf("] }\n");
  } else {
    printf("\n");
  }
  fflush(stdout);

  // Accept connections
  Connection_t * conn = connection_default();
  int res = endpoint_accept(&ep, alpn_slice, &conn);
  if (res != 0) {
    fprintf(stderr, "failed to accept connection");
    return -1;
  }

  // Accept uni directional connection
  RecvStream_t * recv_stream = recv_stream_default();
  res = connection_accept_uni(&conn, &recv_stream);
  if (res != 0) {
    fprintf(stderr, "failed to accept stream");
    return -1;
  }

  uint8_t * recv_buffer = malloc(512);
  slice_mut_uint8_t recv_buffer_slice;
  recv_buffer_slice.ptr = recv_buffer;
  recv_buffer_slice.len = 512;
  int read = recv_stream_read(&recv_stream, recv_buffer_slice);
  if (read == -1) {
    fprintf(stderr, "failed to read data");
    return -1;
  }

  // assume they sent us a nice string
  char * recv_str = malloc(read + 1);
  memcpy(recv_str, recv_buffer, read);
  recv_str[read] = '\0';
  if (json_output) {
    printf("{ \"type\": \"server\", \"status\": \"received\", \"data\": \"%s\" }\n", recv_str);
  } else {
    printf("received: '%s'\n", recv_str);

    // print rtt
    uint64_t rtt = connection_rtt(&conn);
    printf("Estimated RTT: %llu ms\n", rtt);

    // print packet loss, multiple by 100 to get the percentage
    double packet_loss = connection_packet_loss(&conn) * 100;
    printf("Estimated packet loss: %0.2f%%\n", packet_loss);
  }

  fflush(stdout);

  // Cleanup
  free(recv_str);
  recv_stream_free(recv_stream);

  // Accept bi directional connection
  if (json_output) {
    printf("{ \"type\": \"server\", \"status\": \"accepting bi\" }\n");
  } else {
    printf("accepting bi\n");
  }
  recv_stream = recv_stream_default();
  SendStream_t * send_stream = send_stream_default();
  res = connection_accept_bi(&conn, &send_stream,&recv_stream);
  if (res != 0) {
    fprintf(stderr, "failed to accept stream");
    return -1;
  }

  if (json_output) {
    printf("{ \"type\": \"server\", \"status\": \"receiving data\" }\n");
  } else {
    printf("receiving data\n");
  }
  unsigned long bytes_read = 0;
  int err = recv_stream_read_timeout(&recv_stream, recv_buffer_slice, &bytes_read, 5000);
  if (err == ENDPOINT_RESULT_TIMEOUT) {
    fprintf(stderr, "failed to read data before timeout");
    return -1;
    } else if (err == ENDPOINT_RESULT_READ_ERROR) {
    fprintf(stderr, "failed to read data");
    return -1;
  }

  // assume they sent us a nice string
  recv_str = malloc(read + 1);
  memcpy(recv_str, recv_buffer, read);
  recv_str[read] = '\0';
  if (json_output) {
    printf("{ \"type\": \"server\", \"status\": \"received\", \"data\": \"%s\" }\n", recv_str);
  } else {
    printf("received: '%s'\n%d bytes\n", recv_str, read);
  }

  // send response
  slice_ref_uint8_t buffer;
  buffer.ptr = (uint8_t *) &recv_str[0];
  buffer.len = strlen(recv_str);
  if (json_output) {
    printf("{ \"type\": \"server\", \"status\": \"sending data\" }\n");
  } else {
    printf("sending data\n");
  }
  int ret = send_stream_write_timeout(&send_stream, buffer, 5000);
  if (ret == ENDPOINT_RESULT_TIMEOUT) {
    fprintf(stderr, "failed to send data before timeout\n");
    return -1;
  } else if (ret != 0) {
    fprintf(stderr, "failed to send data\n");
    return -1;
  }

  // finish
  ret = send_stream_finish(send_stream);
  if (ret != 0) {
    fprintf(stderr, "failed to finish sending\n");
    return -1;
  }

  // wait for the receiving side to close the connection
  printf("waiting for connection to close");
  ret = connection_closed(conn);
  if (ret != 0) {
    fprintf(stderr, "failed to close connection cleanly\n");
    return -1;
  }

  fflush(stdout);

  // Cleanup
  free(recv_str);
  free(recv_buffer);
  recv_stream_free(recv_stream);
  rust_free_string(relay_url_str);
  rust_free_string(node_id_str);
  node_addr_free(node_addr);
  endpoint_free(ep);

  return 0;
}

int
run_client (
  EndpointConfig_t * config,
  slice_ref_uint8_t alpn_slice,
  char const * node_id_raw,
  char const * relay_url_raw,
  char const ** addrs_raw,
  int addrs_len
)
{
  printf("Starting client...\n");

  // parse node id
  PublicKey_t node_id = public_key_default();
  int ret = public_key_from_base32(node_id_raw, &node_id);
  if (ret != 0) {
    fprintf(stderr, "invalid node id");
    return -1;
  }

  // create node addr
  NodeAddr_t node_addr = node_addr_new(node_id);

  // parse relay url
  if (relay_url_raw != NULL && strlen(relay_url_raw) > 0) {
    Url_t * relay_url = url_default();
    ret = url_from_string(relay_url_raw, &relay_url);
    if (ret != 0) {
      fprintf(stderr, "invalid relay url");
      return -1;
    }
    node_addr_add_relay_url(&node_addr, relay_url);
  }

  // parse direct addrs
  for (int i = 0; i < addrs_len; i++) {
    SocketAddr_t * addr = socket_addr_default();
    ret = socket_addr_from_string(addrs_raw[i], &addr);
    if (ret != 0) {
      fprintf(stderr, "invalid addr");
      return -1;
    }
    node_addr_add_direct_address(&node_addr, addr);
  }

  // setup endpoint
  Endpoint_t * ep = endpoint_default();
  int bind_res = endpoint_bind(config, NULL, NULL, &ep);
  if (bind_res != 0) {
    fprintf(stderr, "failed to bind\n");
    return -1;
  }

  // connect
  Connection_t * conn = connection_default();
  ret = endpoint_connect(&ep, alpn_slice, node_addr, &conn);
  if (ret != 0) {
    fprintf(stderr, "failed to connect to server\n");
    return -1;
  }

  SendStream_t * send_stream = send_stream_default();
  ret = connection_open_uni(&conn, &send_stream);
  if (ret != 0) {
    fprintf(stderr, "failed to establish stream\n");
    return -1;
  }

  // send data
  char * data = "hello world from C";
  slice_ref_uint8_t buffer;
  buffer.ptr = (uint8_t *) &data[0];
  buffer.len = strlen(data);

  ret = send_stream_write(&send_stream, buffer);
  if (ret != 0) {
    fprintf(stderr, "failed to send data\n");
    return -1;
  }

  // finish
  ret = send_stream_finish(send_stream);
  if (ret != 0) {
    fprintf(stderr, "failed to finish sending\n");
    return -1;
  }

  // print rtt
  uint64_t rtt = connection_rtt(&conn);
  printf("Estimated RTT: %llu ms\n", rtt);

  // print packet loss, multiple by 100 to get the percentage
  double packet_loss = connection_packet_loss(&conn) * 100;
  printf("Estimated packet loss: %0.2f%%\n", packet_loss);

  // Open bidirectional stream
  printf("open_bi\n");
  send_stream = send_stream_default();
  RecvStream_t * recv_stream = recv_stream_default();
  ret = connection_open_bi(&conn, &send_stream, &recv_stream);
  if (ret != 0) {
    fprintf(stderr, "failed to establish stream\n");
    return -1;
  }

  // send data
  buffer.ptr = (uint8_t *) &data[0];
  buffer.len = strlen(data);

  printf("sending data\n");
  ret = send_stream_write(&send_stream, buffer);
  if (ret != 0) {
    fprintf(stderr, "failed to send data\n");
    return -1;
  }

  uint8_t * recv_buffer = malloc(512);
  slice_mut_uint8_t recv_buffer_slice;
  recv_buffer_slice.ptr = recv_buffer;
  recv_buffer_slice.len = 512;

  printf("receving data\n");
  int read = recv_stream_read(&recv_stream, recv_buffer_slice);
  if (read == -1) {
    fprintf(stderr, "failed to read data");
    return -1;
  }

  // assume they sent us a nice string
  char * recv_str = malloc(read + 1);
  memcpy(recv_str, recv_buffer, read);
  recv_str[read] = '\0';
  printf("received: '%s'\n", recv_str);

  // finish
  ret = send_stream_finish(send_stream);
  if (ret != 0) {
    fprintf(stderr, "failed to finish sending\n");
    return -1;
  }

  // indicate to the server that you want to close the connection
  printf("closing connection\n");
  connection_close(conn);
  printf("connection closed");

  // cleanup
  free(recv_str);
  free(recv_buffer);
  recv_stream_free(recv_stream);
  return 0;
}

int
main (int argc, char const * const argv[])
{
  iroh_enable_tracing();

  if (argc < 2) {
    fprintf(stderr, "Usage: must supply at least 'client' or 'server'\n");
    return -1;
  }

  // setup iroh endpoint configuration
  char alpn[] = "/cool/alpn/1";
  slice_ref_uint8_t alpn_slice;
  alpn_slice.ptr = (uint8_t *) &alpn[0];
  alpn_slice.len = strlen(alpn);

  EndpointConfig_t config = endpoint_config_default();
  endpoint_config_add_alpn(&config, alpn_slice);
  config.discovery_cfg = DISCOVERY_CONFIG_ALL;

  // run server or client
  if (strcmp(argv[1], "client") == 0) {
    if (argc < 3) {
      fprintf(stderr, "client must be supplied <node id> <relay-url> <addr1> .. <addrn>");
      return -1;
    }
    char const * node_id = argv[2];
    char const * relay_url = NULL;
    char const **addrs = NULL;
    int addrs_len = 0;

    if (argc > 3) {
      relay_url = argv[3];
    }

    if (argc > 4) {
      addrs_len = argc - 4;
      addrs = malloc(addrs_len * sizeof(char const*));
      for (int i = 0; i < addrs_len; i++) {
        addrs[i] = argv[4 + i];
      }
    }

    int ret = run_client(&config, alpn_slice, node_id, relay_url, addrs, addrs_len);
    if (ret != 0) {
      return ret;
    }

    // cleanup
    free(addrs);

  } else if (strcmp(argv[1], "server") == 0) {
    bool json_output = false;
    if (argc > 2 && strcmp(argv[2], "--json") == 0) {
      json_output = true;
    }
    int ret = run_server(&config, alpn_slice, json_output);
    if (ret != 0) {
      return ret;
    }
  } else {
    fprintf(stderr, "invalid arg: %s\n", argv[2]);
    return -1;
  }

  // cleanup
  endpoint_config_free(config);

  return EXIT_SUCCESS;
}
