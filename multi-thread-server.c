#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "irohnet.h"

int run_server(MagicEndpoint_t *ep, slice_ref_uint8_t alpn_slice, bool json_output)
{
    if (json_output)
    {
        printf("{ \"type\": \"server\", \"status\": \"starting\" }\n");
    }
    else
    {
        printf("Starting server...\n");
    }

    // Bind

    // Accept connections
    Connection_t *conn = connection_default();
    int res = magic_endpoint_accept(&ep, alpn_slice, &conn);
    if (res != 0)
    {
        fprintf(stderr, "failed to accept connection");
        return -1;
    }

    // Accept uni directional connection
    RecvStream_t *recv_stream = recv_stream_default();
    res = connection_accept_uni(&conn, &recv_stream);
    if (res != 0)
    {
        fprintf(stderr, "failed to accept stream");
        return -1;
    }

    uint8_t *recv_buffer = malloc(512);
    slice_mut_uint8_t recv_buffer_slice;
    recv_buffer_slice.ptr = recv_buffer;
    recv_buffer_slice.len = 512;
    int read = recv_stream_read(&recv_stream, recv_buffer_slice);
    if (read == -1)
    {
        fprintf(stderr, "failed to read data");
        return -1;
    }

    // assume they sent us a nice string
    char *recv_str = malloc(read + 1);
    memcpy(recv_str, recv_buffer, read);
    recv_str[read] = '\0';
    if (json_output)
    {
        printf("{ \"type\": \"server\", \"status\": \"received\", \"data\": \"%s\" }\n", recv_str);
    }
    else
    {
        printf("received: '%s'\n", recv_str);

        // print rtt
        uint64_t rtt = connection_rtt(&conn);
        printf("Estimated RTT: %llu ms\n", rtt);
    }

    fflush(stdout);

    // Cleanup
    free(recv_str);
    recv_stream_free(recv_stream);

    // Accept bi directional connection
    printf("accepting bi\n");
    recv_stream = recv_stream_default();
    SendStream_t *send_stream = send_stream_default();
    res = connection_accept_bi(&conn, &send_stream, &recv_stream);
    if (res != 0)
    {
        fprintf(stderr, "failed to accept stream");
        return -1;
    }

    printf("receving data\n");
    read = recv_stream_read(&recv_stream, recv_buffer_slice);
    if (read == -1)
    {
        fprintf(stderr, "failed to read data");
        return -1;
    }

    // assume they sent us a nice string
    recv_str = malloc(read + 1);
    memcpy(recv_str, recv_buffer, read);
    recv_str[read] = '\0';
    if (json_output)
    {
        // ..
    }
    else
    {
        printf("received: '%s'\n", recv_str);
    }

    // send response
    slice_ref_uint8_t buffer;
    buffer.ptr = (uint8_t *)&recv_str[0];
    buffer.len = strlen(recv_str);
    printf("sending data\n");
    int ret = send_stream_write(&send_stream, buffer);
    if (ret != 0)
    {
        fprintf(stderr, "failed to send data\n");
        return -1;
    }

    // finish
    ret = send_stream_finish(send_stream);
    if (ret != 0)
    {
        fprintf(stderr, "failed to finish sending\n");
        return -1;
    }

    // Cleanup
    free(recv_str);
    free(recv_buffer);
    recv_stream_free(recv_stream);
    connection_free(conn);
    magic_endpoint_free(ep);

    return 0;
}

// Define a structure to pass multiple parameters to the pthread functions
typedef struct
{
    MagicEndpointConfig_t *config;
    slice_ref_uint8_t alpn_slice;
    MagicEndpoint_t *ep;
    bool json_output;     // For server
    const char *node_id;  // For client
    const char *derp_url; // For client
    const char **addrs;   // For client
    int addrs_len;        // For client
} ThreadParam;

// Wrapper function for the server
void *server_thread_func(void *arg)
{
    ThreadParam *params = (ThreadParam *)arg;
    run_server(params->ep, params->alpn_slice, params->json_output);
    pthread_exit(NULL);
}

int main(int argc, char const *const argv[])
{
    iroh_enable_tracing();

    pthread_t server_threads[2];
    // pthread_t client_threads[2];
    ThreadParam server_params[2];
    // ThreadParam client_params[2];

    // Initialize parameters for each thread, including different ALPNs
    char alpn1[] = "/cool/alpn/1";
    char alpn2[] = "/cool/alpn/2";

    // Assuming server and client specific parameters are initialized here...

    // Server thread 1
    server_params[0].alpn_slice.ptr = (uint8_t *)&alpn1[0];
    server_params[0].alpn_slice.len = strlen(alpn1);
    server_params[0].json_output = false; // Or true, based on your requirement
    MagicEndpointConfig_t config = magic_endpoint_config_default();
    magic_endpoint_config_add_alpn(&config, server_params[0].alpn_slice);
    server_params[0].config = &config;

    // Server thread 2 with different ALPN
    server_params[1].alpn_slice.ptr = (uint8_t *)&alpn2[0];
    server_params[1].alpn_slice.len = strlen(alpn2);
    server_params[1].json_output = false; // Or true
    magic_endpoint_config_add_alpn(&config, server_params[1].alpn_slice);
    server_params[1].config = &config;

    MagicEndpoint_t *ep = magic_endpoint_default();
    int bind_res = magic_endpoint_bind(&config, 0, &ep);
    if (bind_res != 0)
    {
        fprintf(stderr, "failed to bind server\n");
        return -1;
    }

    // Print details
    NodeAddr_t my_addr = node_addr_default();
    int addr_res = magic_endpoint_my_addr(&ep, &my_addr);
    if (addr_res != 0)
    {
        fprintf(stderr, "faile to get my address");
        return -1;
    }
    char *node_id_str = public_key_as_base32(&my_addr.node_id);
    char *derp_url_str = url_as_str(my_addr.derp_url);

    printf("Listening on:\nNode Id: %s\nDerp: %s\nAddrs:\n", node_id_str, derp_url_str);

    // iterate over the direct addresses
    for (int i = 0; i < my_addr.direct_addresses.len; i++)
    {
        SocketAddr_t const *addr = node_addr_direct_addresses_nth(&my_addr, i);
        char *socket_str = socket_addr_as_str(addr);
        printf("  - %s\n", socket_str);
        rust_free_string(socket_str);
    }
    printf("\n");
    fflush(stdout);

    server_params[0].ep = ep;
    server_params[1].ep = ep;

    pthread_create(&server_threads[0], NULL, server_thread_func, (void *)&server_params[0]);
    //pthread_create(&server_threads[1], NULL, server_thread_func, (void *)&server_params[1]);

    // Client threads would be similar, using client_thread_func and client_params
    // Initialize client_params with necessary parameters
    // pthread_create(&client_threads[0], NULL, client_thread_func, (void *)&client_params[0]);
    // pthread_create(&client_threads[1], NULL, client_thread_func, (void *)&client_params[1]);

    // Wait for server threads to complete
    pthread_join(server_threads[0], NULL);
    pthread_join(server_threads[1], NULL);

    rust_free_string(derp_url_str);
    rust_free_string(node_id_str);
    node_addr_free(my_addr);

    // Wait for client threads to complete
    // pthread_join(client_threads[0], NULL);
    // pthread_join(client_threads[1], NULL);

    return 0;
}
