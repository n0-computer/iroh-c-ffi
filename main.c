/* Example program testing the api */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "irohnet.h"

int
main (int argc, char const * const argv[])
{

  // setup magic endpoint configuration

  char alpn[] = "/cool/alpn/1";
  slice_ref_uint8_t * alpn_slice = malloc(sizeof(slice_ref_uint8_t));
  alpn_slice->ptr = (uint8_t *) &alpn[0];
  alpn_slice->len = strlen(alpn);

  MagicEndpointConfig_t config = magic_endpoint_config_default();
  magic_endpoint_config_add_alpn(&config, *alpn_slice);

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
    char * node_id_str = public_key_as_base32(&my_addr.node_id);
    char * derp_url_str = url_as_str(my_addr.derp_url);
    printf(
      "Listening on:\nNode Id: %s\nDerp: %s\nAddrs:\n",
      node_id_str,
      derp_url_str
    );

    for (int i = 0; i < my_addr.direct_addresses.len; i++) {
      SocketAddr_t const * addr = node_addr_direct_addresses_nth(&my_addr, i);
      char * socket_str = socket_addr_as_str(addr);
      printf("  - %s\n", socket_str);
      rust_free_string(socket_str);
    }
    printf("\n");

    // Accept connections



    // Cleanup
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
  free(alpn_slice);

  return EXIT_SUCCESS;
}
