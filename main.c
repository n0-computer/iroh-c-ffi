/* Example program testing the api */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "irohnet.h"

int
main (int argc, char const * const argv[])
{
  if (argc < 2) {
    fprintf(stderr, "Usage: must supply at least client or server\n");
    return -1;
  }

  // setup magic endpoint configuration
  char alpn[] = "/cool/alpn/1";
  slice_ref_uint8_t alpn_slice;
  alpn_slice.ptr = (uint8_t *) &alpn[0];
  alpn_slice.len = strlen(alpn);

  MagicEndpointConfig_t config = magic_endpoint_config_default();
  magic_endpoint_config_add_alpn(&config, alpn_slice);

  // run server or client
  if (strcmp(argv[1], "client") == 0) {
    printf("starting client\n");

  } else if (strcmp(argv[1], "server") == 0) {
    printf("Starting server...\n");

    // Bind
    MagicEndpoint_t * ep = magic_endpoint_default();
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
    char * node_id_str = public_key_as_base32(&my_addr.node_id);
    char * derp_url_str = url_as_str(my_addr.derp_url);
    printf(
      "Listening on:\nNode Id: %s\nDerp: %s\nAddrs:\n",
      node_id_str,
      derp_url_str
    );

    // iterate over the direct addresses
    for (int i = 0; i < my_addr.direct_addresses.len; i++) {
      SocketAddr_t const * addr = node_addr_direct_addresses_nth(&my_addr, i);
      char * socket_str = socket_addr_as_str(addr);
      printf("  - %s\n", socket_str);
      rust_free_string(socket_str);
    }
    printf("\n");

    // Accept connections
    RecvStream_t * recv_stream = magic_endpoint_recv_stream_default();
    int res = magic_endpoint_accept_uni(&ep, alpn_slice, &recv_stream);
    if (res != 0) {
      fprintf(stderr, "failed to accept connection");
      return -1;
    }

    uint8_t * recv_buffer = malloc(512);
    slice_mut_uint8_t recv_buffer_slice;
    recv_buffer_slice.ptr = recv_buffer;
    recv_buffer_slice.len = 512;
    int read = magic_endpoint_recv_stream_read(&recv_stream, recv_buffer_slice);
    if (read == -1) {
      fprintf(stderr, "failed to read data");
      return -1;
    }

    // assume they sent us a nice string
    char * recv_str = malloc(read + 1);
    memcpy(recv_str, recv_buffer, read);
    recv_str[read] = '\0';
    printf("received: '%s'", recv_str);

    // Cleanup
    free(recv_str);
    free(recv_buffer);
    magic_endpoint_recv_stream_free(recv_stream);
    rust_free_string(derp_url_str);
    rust_free_string(node_id_str);
    node_addr_free(my_addr);
    magic_endpoint_free(ep);
  } else {
    fprintf(stderr, "invalid arg: %s\n", argv[1]);
    return -1;
  }

  // cleanup
  magic_endpoint_config_free(config);

  return EXIT_SUCCESS;
}
