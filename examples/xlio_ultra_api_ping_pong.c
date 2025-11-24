/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

/*
 * XLIO Ultra API Ping-Pong Example
 *
 * This example demonstrates the XLIO Ultra API usage in a simple ping-pong client-server
 * application.
 *
 * Build: gcc -o examples/xlio_ultra_api_ping_pong examples/xlio_ultra_api_ping_pong.c -libverbs
 *
 * Usage (help)  : ./examples/xlio_ultra_api_ping_pong --help
 * Usage (server): LD_PRELOAD=libxlio.so ./examples/xlio_ultra_api_ping_pong -s -i 192.168.1.100
 * Usage (client): LD_PRELOAD=libxlio.so ./examples/xlio_ultra_api_ping_pong -c -i 192.168.1.100
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <mellanox/xlio_extra.h>
#include <infiniband/verbs.h>

/* Application configuration */
struct app_config {
    bool is_server;
    const char *ip;
    const char *bind_ip; /* Local IP to bind client socket to */
    unsigned short port;
    int ping_count;
    int timeout_seconds; /* Application timeout in seconds (0 = no timeout) */
};

/* Application state */
struct app_state {
    struct xlio_api_t *api; /* XLIO Ultra API function pointers */
    xlio_poll_group_t group; /* Polling group handle */
    xlio_socket_t sock; /* Main socket handle (server: listening, client: connection) */
    xlio_socket_t client_sock; /* Incoming socket handle (server only) */

    /* Client state */
    int pings_sent;
    int pongs_received;

    /* Common state */
    bool terminated;
    bool quit;

    /* TX zero-copy support */
    struct ibv_pd *pd;
    struct ibv_mr *mr_buf;
    /* TX buffer pool */
    char *tx_buffers; /* Memory block for all TX buffers */
    char **pool_stack; /* Stack of available buffer pointers */
    int pool_top; /* Top of stack (-1 when empty) */

    /* RTT measurement */
    struct timespec ping_sent_time; /* Timestamp when last ping was sent */
};

/* Default configuration */
static struct app_config g_config = {.is_server = false,
                                     .ip = NULL, /* Must be specified for client */
                                     .bind_ip = NULL, /* No client bind by default */
                                     .port = 8080,
                                     .ping_count = 3,
                                     .timeout_seconds = 0}; /* No timeout by default */

static struct app_state g_state = {0};

/* Message constants */
#define MSG_PING "ping"
#define MSG_PONG "pong"
#define MSG_EXIT "exit"

/* User data constants for socket identification */
#define USERDATA_SERVER_LISTEN 0xdeadbeef
#define USERDATA_SERVER_CLIENT 0xcafebabe
#define USERDATA_CLIENT        0xfeedface

/* TX buffer pool configuration */
#define TX_BUFFER_COUNT 128 /* Number of TX buffers in the pool */
#define TX_BUFFER_SIZE  1024 /* Size of each TX buffer in bytes */

/*
 * Forward declarations
 */
static int parse_command_line(int argc, char **argv);
static int init_xlio_ultra_api(void);
static int create_polling_group(void);
static int run_server_mode(void);
static int run_client_mode(void);
static void cleanup_resources(void);

/* XLIO Ultra API callback implementations */
static void memory_cb(void *data, size_t size, size_t page_size);
static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value);
static void socket_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op);
static void socket_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                         struct xlio_buf *buf);
static void socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent,
                             uintptr_t parent_userdata_sq);

/* TX buffer pool management */
static int init_tx_buffer_pool(void);
static int register_tx_buffer_pool(xlio_socket_t sock);
static char *get_tx_buffer(void);
static void return_tx_buffer(char *buffer_ptr);
static void cleanup_tx_buffer_pool(void);

/* Utility functions */
static int send_message(xlio_socket_t sock, const char *msg);
static int send_ping_with_timing(xlio_socket_t sock);
static double calculate_rtt_microseconds(const struct timespec *start, const struct timespec *end);
static void process_received_message(xlio_socket_t sock, const char *msg, size_t len);

/* Timeout handling */
static void timeout_handler(int sig);
static int setup_timeout(int timeout_seconds);

/*
 * Main application entry point
 */
int main(int argc, char **argv)
{
    int rc;

    printf("XLIO Ultra API Ping-Pong Example\n");
    printf("================================\n");

    /* Parse command line arguments - auxiliary logic */
    rc = parse_command_line(argc, argv);
    if (rc != 0) {
        return EXIT_FAILURE;
    }

    /*
     * XLIO Ultra API Initialization
     * =============================
     * The first step is to initialize the XLIO Ultra API using indirect function calls.
     * This allows the application to work with LD_PRELOAD without linking to libxlio.
     */
    rc = init_xlio_ultra_api();
    if (rc != 0) {
        fprintf(stderr, "Failed to initialize XLIO Ultra API\n");
        return EXIT_FAILURE;
    }

    /*
     * Create Polling Group
     * ===================
     * Create a polling group with event callbacks for socket event management.
     */
    rc = create_polling_group();
    if (rc != 0) {
        fprintf(stderr, "Failed to create polling group\n");
        cleanup_resources();
        return EXIT_FAILURE;
    }

    /*
     * Initialize TX Buffer Pool
     * ========================
     * Allocate memory for TX buffers early. Memory registration will be done
     * later after obtaining a protection domain from a connected socket.
     */
    rc = init_tx_buffer_pool();
    if (rc != 0) {
        fprintf(stderr, "Failed to initialize TX buffer pool\n");
        cleanup_resources();
        return EXIT_FAILURE;
    }

    /* Run in appropriate mode */
    if (g_config.is_server) {
        printf("Running in server mode on %s:%u\n", g_config.ip ? g_config.ip : "*", g_config.port);
        rc = run_server_mode();
    } else {
        if (g_config.bind_ip) {
            printf("Running in client mode, connecting to %s:%u (bind to %s), ping count=%d\n",
                   g_config.ip, g_config.port, g_config.bind_ip, g_config.ping_count);
        } else {
            printf("Running in client mode, connecting to %s:%u, ping count=%d\n", g_config.ip,
                   g_config.port, g_config.ping_count);
        }
        rc = run_client_mode();
    }

    /* Cleanup resources */
    cleanup_resources();

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*
 * Print usage information
 */
static void print_usage(const char *program_name)
{
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nMode Selection (required):\n");
    printf("  -s, --server              Run in server mode\n");
    printf("  -c, --client              Run in client mode\n");
    printf("\nConnection Options:\n");
    printf("  -i, --ip <IP>             Server IP address (required for client mode)\n");
    printf("  -p, --port <PORT>         Port number (default: 8080)\n");
    printf("  -I, --client-ip <IP>      Local IP address to bind client socket to\n");
    printf("\nClient Options:\n");
    printf("  -n, --count <COUNT>       Number of ping messages to send (default: 3)\n");
    printf("\nGeneral Options:\n");
    printf("  -t, --timeout <SECONDS>   Timeout in seconds (0 = no timeout, default: 0)\n");
    printf("  -h, --help                Show this help message\n");
    printf("\nExamples:\n");
    printf("  Server:     LD_PRELOAD=install/lib/libxlio.so %s --server --ip 192.168.1.100\n",
           program_name);
    printf("  Client:     LD_PRELOAD=install/lib/libxlio.so %s --client --ip 192.168.1.100\n",
           program_name);
    printf("  Client+bind: LD_PRELOAD=install/lib/libxlio.so %s --client --ip 192.168.1.100 "
           "--client-ip 192.168.1.101 --count 5\n",
           program_name);
}

/*
 * Parse command line arguments using getopt_long
 */
static int parse_command_line(int argc, char **argv)
{
    static struct option long_options[] = {{"server", no_argument, NULL, 's'},
                                           {"client", no_argument, NULL, 'c'},
                                           {"ip", required_argument, NULL, 'i'},
                                           {"port", required_argument, NULL, 'p'},
                                           {"client-ip", required_argument, NULL, 'I'},
                                           {"count", required_argument, NULL, 'n'},
                                           {"timeout", required_argument, NULL, 't'},
                                           {"help", no_argument, NULL, 'h'},
                                           {NULL, 0, NULL, 0}};

    int rc;
    int option;
    int option_index = 0;
    bool mode_specified = false;

    /* Reset global variables for clean parsing */
    optind = 1;

    while ((option = getopt_long(argc, argv, "sci:p:I:n:t:h", long_options, &option_index)) != -1) {
        switch (option) {
        case 's':
            if (mode_specified) {
                fprintf(stderr, "Error: Cannot specify both server and client modes\n");
                return -1;
            }
            g_config.is_server = true;
            mode_specified = true;
            break;

        case 'c':
            if (mode_specified) {
                fprintf(stderr, "Error: Cannot specify both server and client modes\n");
                return -1;
            }
            g_config.is_server = false;
            mode_specified = true;
            break;

        case 'i':
            g_config.ip = optarg;
            break;

        case 'p':
            g_config.port = atoi(optarg);
            if (g_config.port <= 0 || g_config.port > 65535) {
                fprintf(stderr, "Error: Invalid port number: %s\n", optarg);
                return -1;
            }
            break;

        case 'I':
            g_config.bind_ip = optarg;
            break;

        case 'n':
            g_config.ping_count = atoi(optarg);
            if (g_config.ping_count <= 0) {
                fprintf(stderr, "Error: Invalid ping count: %s\n", optarg);
                return -1;
            }
            break;

        case 't':
            g_config.timeout_seconds = atoi(optarg);
            if (g_config.timeout_seconds < 0) {
                fprintf(stderr, "Error: Timeout must be non-negative (0 = no timeout)\n");
                return -1;
            }
            break;

        case 'h':
            print_usage(argv[0]);
            return -1;

        case '?':
            /* getopt_long already printed error message */
            fprintf(stderr, "Use --help for usage information.\n");
            return -1;

        default:
            fprintf(stderr, "Error: Unknown option\n");
            return -1;
        }
    }

    /* Check for extra arguments */
    if (optind < argc) {
        fprintf(stderr, "Error: Unexpected arguments:");
        while (optind < argc) {
            fprintf(stderr, " %s", argv[optind++]);
        }
        fprintf(stderr, "\nUse --help for usage information.\n");
        return -1;
    }

    /* Validate that mode was specified */
    if (!mode_specified) {
        fprintf(stderr, "Error: Must specify either --server (-s) or --client (-c) mode\n");
        print_usage(argv[0]);
        return -1;
    }

    /* Client mode validation */
    if (!g_config.is_server) {
        if (!g_config.ip || g_config.ip[0] == '\0') {
            fprintf(stderr, "Error: Client mode requires server IP address (--ip)\n");
            return -1;
        }
    }

    /*
     * Setup Timeout (if specified)
     * ============================
     * Configure application timeout using SIGALRM signal.
     */
    if (g_config.timeout_seconds > 0) {
        rc = setup_timeout(g_config.timeout_seconds);
        if (rc != 0) {
            fprintf(stderr, "Failed to setup timeout\n");
            return -1;
        }
        printf("Application timeout set to %d seconds\n", g_config.timeout_seconds);
    }

    return 0;
}

/*
 * XLIO Ultra API Initialization using indirect function calls
 * ===========================================================
 * This function demonstrates how to initialize XLIO Ultra API using the indirect
 * interface from xlio_extra.h. This approach allows the application to work with
 * LD_PRELOAD without explicit linking to libxlio. This function handles API
 * discovery, compatibility validation, and XLIO initialization.
 */
static int init_xlio_ultra_api(void)
{
    int rc;

    /*
     * Step 1: Obtain XLIO API function pointers
     * ==========================================
     * Use xlio_get_api() from <mellanox/xlio_extra.h> to retrieve the function pointer structure.
     * This works when libxlio is preloaded with LD_PRELOAD.
     */
    g_state.api = xlio_get_api();
    if (!g_state.api) {
        fprintf(stderr, "Failed to get XLIO API. Ensure libxlio is preloaded with LD_PRELOAD.\n");
        return -1;
    }

    /*
     * Step 2: Validate API compatibility
     * ==================================
     * Check capabilities to ensure compatibility.
     */
    if (!(g_state.api->cap_mask & XLIO_EXTRA_API_XLIO_ULTRA)) {
        fprintf(stderr, "XLIO Ultra API not available. Check libxlio version.\n");
        return -1;
    }

    printf("XLIO Ultra API initialized successfully\n");

    /*
     * Step 3: Initialize XLIO with memory callback
     * ============================================
     * Set up initialization attributes with memory allocation callback.
     * The memory callback is called when XLIO allocates memory regions.
     */
    struct xlio_init_attr init_attr = {.flags = 0,
                                       .memory_cb = memory_cb,
                                       .memory_alloc = NULL, /* Use default internal allocator */
                                       .memory_free = NULL};

    rc = g_state.api->xlio_init_ex(&init_attr);
    if (rc != 0) {
        fprintf(stderr, "Failed to initialize XLIO: %s\n", strerror(errno));
        return rc;
    }

    printf("XLIO initialized successfully\n");

    return 0;
}

/*
 * Create polling group with event callbacks
 * =========================================
 * Create a polling group with event callbacks. The polling group manages
 * sockets and their events through registered callback functions.
 */
static int create_polling_group(void)
{
    int rc;

    /*
     * Create polling group with event callbacks
     * ========================================
     * The polling group manages sockets and their events through registered
     * callback functions. Event callbacks are registered per group, allowing
     * different handling logic for different types of connections.
     */
    struct xlio_poll_group_attr group_attr = {
        .flags = 0,
        .socket_event_cb = socket_event_cb, /* Required: socket state changes */
        .socket_comp_cb = socket_comp_cb, /* Optional: zero-copy completions */
        .socket_rx_cb = socket_rx_cb, /* Optional: receive data */
        .socket_accept_cb = socket_accept_cb /* Optional: new connections (server) */
    };

    rc = g_state.api->xlio_poll_group_create(&group_attr, &g_state.group);
    if (rc != 0) {
        fprintf(stderr, "Failed to create polling group: %s\n", strerror(errno));
        return rc;
    }

    printf("Polling group created successfully\n");

    return 0;
}

/*
 * Server mode implementation
 * =========================
 * Demonstrates listening socket creation, connection acceptance, and message echo.
 */
static int run_server_mode(void)
{
    int rc;

    /*
     * Step 1: Create listening socket
     * ==============================
     * Create a socket associated with the polling group for accepting connections.
     */
    struct xlio_socket_attr sock_attr = {
        .flags = 0,
        .domain = AF_INET,
        .group = g_state.group,
        .userdata_sq = USERDATA_SERVER_LISTEN /* Used to identify socket in callbacks */
    };

    rc = g_state.api->xlio_socket_create(&sock_attr, &g_state.sock);
    if (rc != 0) {
        fprintf(stderr, "Failed to create server socket: %s\n", strerror(errno));
        return rc;
    }

    printf("Server socket created\n");

    /*
     * Step 2: Bind socket to address
     * ==============================
     */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_config.port);

    if (g_config.ip) {
        rc = inet_aton(g_config.ip, &addr.sin_addr);
        if (rc == 0) {
            fprintf(stderr, "Invalid IP address: %s\n", g_config.ip);
            return -1;
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    rc = g_state.api->xlio_socket_bind(g_state.sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        fprintf(stderr, "Failed to bind server socket: %s\n", strerror(errno));
        return rc;
    }

    printf("Server socket bound to %s:%u\n", g_config.ip ? g_config.ip : "*", g_config.port);

    /*
     * Step 3: Start listening for connections
     * =======================================
     * Note: socket_accept_cb must be registered in the polling group for this to work.
     */
    rc = g_state.api->xlio_socket_listen(g_state.sock);
    if (rc != 0) {
        fprintf(stderr, "Failed to listen on server socket: %s\n", strerror(errno));
        return rc;
    }

    printf("Server listening for connections...\n");

    /*
     * Step 4: Main event processing loop
     * ==================================
     * Poll for events until the application should quit.
     * All socket events are handled via registered callbacks.
     */
    while (!g_state.quit) {
        g_state.api->xlio_poll_group_poll(g_state.group);
    }

    printf("Server shutting down...\n");

    return 0;
}

/*
 * Client mode implementation
 * ==========================
 * Demonstrates socket connection, message sending, and response handling.
 */
static int run_client_mode(void)
{
    int rc;

    /*
     * Step 1: Create client socket
     * ============================
     */
    struct xlio_socket_attr sock_attr = {.flags = 0,
                                         .domain = AF_INET,
                                         .group = g_state.group,
                                         .userdata_sq = USERDATA_CLIENT};

    rc = g_state.api->xlio_socket_create(&sock_attr, &g_state.sock);
    if (rc != 0) {
        fprintf(stderr, "Failed to create client socket: %s\n", strerror(errno));
        return rc;
    }

    printf("Client socket created\n");

    /*
     * Step 2: Bind client socket to local IP (if specified)
     * =====================================================
     * Optional step to bind the client socket to a specific local IP address.
     */
    if (g_config.bind_ip) {
        struct sockaddr_in bind_addr = {0};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = 0; /* Let system choose port */

        rc = inet_aton(g_config.bind_ip, &bind_addr.sin_addr);
        if (rc == 0) {
            fprintf(stderr, "Invalid bind IP address: %s\n", g_config.bind_ip);
            return -1;
        }

        rc = g_state.api->xlio_socket_bind(g_state.sock, (struct sockaddr *)&bind_addr,
                                           sizeof(bind_addr));
        if (rc != 0) {
            fprintf(stderr, "Failed to bind client socket to %s: %s\n", g_config.bind_ip,
                    strerror(errno));
            return rc;
        }

        printf("Client socket bound to local IP %s\n", g_config.bind_ip);
    }

    /*
     * Step 3: Connect to server
     * =========================
     * The connection is asynchronous. Connection establishment is indicated
     * by XLIO_SOCKET_EVENT_ESTABLISHED event in socket_event_cb.
     */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_config.port);

    rc = inet_aton(g_config.ip, &addr.sin_addr);
    if (rc == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", g_config.ip);
        return -1;
    }

    rc = g_state.api->xlio_socket_connect(g_state.sock, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        fprintf(stderr, "Failed to connect to server: %s\n", strerror(errno));
        return rc;
    }

    printf("Connecting to %s:%u...\n", g_config.ip, g_config.port);

    /*
     * Step 4: Main event processing loop
     * ==================================
     * Poll for events until the application should quit.
     * Connection establishment and ping-pong logic are handled in callbacks.
     */
    while (!g_state.quit) {
        g_state.api->xlio_poll_group_poll(g_state.group);
    }

    printf("Client finished\n");

    rc = 0;
    if (g_state.pongs_received != g_config.ping_count) {
        fprintf(stderr, "Failed to receive requested number of replies:\n");
        fprintf(stderr, "  User requested %d pings\n", g_config.ping_count);
        fprintf(stderr, "  Sent %d pings\n", g_state.pings_sent);
        fprintf(stderr, "  Received %d pongs\n", g_state.pongs_received);
        rc = -1;
    }
    return rc;
}

/*
 * Cleanup resources
 * ================
 * Properly destroy sockets, polling group, and exit XLIO.
 */
static void cleanup_resources(void)
{
    int rc;

    if (!g_state.api) {
        return;
    }

    /* Destroy client socket (server mode) */
    if (g_state.client_sock) {
        rc = g_state.api->xlio_socket_destroy(g_state.client_sock);
        if (rc != 0) {
            fprintf(stderr, "Failed to destroy client socket\n");
        }

        /* Wait for termination event */
        while (!g_state.terminated) {
            g_state.api->xlio_poll_group_poll(g_state.group);
        }
    }

    /* Destroy main socket */
    if (g_state.sock) {
        g_state.terminated = false;
        rc = g_state.api->xlio_socket_destroy(g_state.sock);
        if (rc != 0) {
            fprintf(stderr, "Failed to destroy socket\n");
        }

        /* Wait for termination event */
        while (!g_state.terminated) {
            g_state.api->xlio_poll_group_poll(g_state.group);
        }
    }

    /* Destroy polling group */
    if (g_state.group) {
        rc = g_state.api->xlio_poll_group_destroy(g_state.group);
        if (rc != 0) {
            fprintf(stderr, "Failed to destroy polling group\n");
        }
    }

    /* Deregister and free memory for TX buffer pool */
    cleanup_tx_buffer_pool();

    /* Finalize XLIO */
    rc = g_state.api->xlio_exit();
    if (rc != 0) {
        fprintf(stderr, "Failed to finalize XLIO\n");
    }

    printf("Resources cleaned up\n");
}

/*
 * XLIO Ultra API Callback Implementations
 * =======================================
 */

/*
 * Memory allocation callback
 * =========================
 * Called when XLIO allocates memory regions for RX buffers.
 * User can use this information to prepare the memory for some application logic.
 */
static void memory_cb(void *data, size_t size, size_t page_size)
{
    printf("XLIO allocated memory: addr=%p size=%zu page_size=%zu\n", data, size, page_size);
}

/*
 * Socket event callback
 * ====================
 * Handles socket state changes: connection establishment, errors, termination.
 */
static void socket_event_cb(xlio_socket_t sock, uintptr_t userdata_sq, int event, int value)
{
    switch (event) {
    case XLIO_SOCKET_EVENT_ESTABLISHED:
        printf("Connection established (socket userdata=%lx)\n", userdata_sq);

        if (userdata_sq == USERDATA_CLIENT) {
            /* Register TX buffer memory for client-side connections */
            if (register_tx_buffer_pool(sock) != 0) {
                fprintf(stderr, "Failed to register TX buffer memory\n");
            }

            /* Start ping-pong sequence for client */
            send_ping_with_timing(sock);
            g_state.pings_sent = 1;
            printf("Sent ping #%d\n", g_state.pings_sent);
        } else {
            /* Server side accepts connections with the socket_accept_cb callback */
            fprintf(stderr,
                    "Unexpected XLIO_SOCKET_EVENT_ESTABLISHED event for socket with userdata=%lx\n",
                    userdata_sq);
        }
        break;

    case XLIO_SOCKET_EVENT_TERMINATED:
        printf("Socket terminated (socket userdata=%lx)\n", userdata_sq);
        g_state.terminated = true;
        break;

    case XLIO_SOCKET_EVENT_CLOSED:
        printf("Connection closed by peer (socket userdata=%lx)\n", userdata_sq);
        break;

    case XLIO_SOCKET_EVENT_ERROR:
        printf("Socket error (socket userdata=%lx): %s\n", userdata_sq, strerror(value));
        g_state.quit = true;
        break;

    default:
        printf("Unknown socket event %d (socket userdata=%lx)\n", event, userdata_sq);
        break;
    }
}

/*
 * Zero-copy completion callback
 * ============================
 * Called when zero-copy send operations complete, allowing buffer reuse.
 * Returns the buffer to the TX buffer pool.
 */
static void socket_comp_cb(xlio_socket_t sock, uintptr_t userdata_sq, uintptr_t userdata_op)
{
    char *buffer_ptr = (char *)userdata_op;
    printf("Zero-copy send completed (socket userdata=%lx, buffer=%p)\n", userdata_sq,
           (void *)buffer_ptr);

    return_tx_buffer(buffer_ptr);
}

/*
 * Receive data callback
 * ====================
 * Called when TCP payload arrives. Processes ping-pong messages.
 */
static void socket_rx_cb(xlio_socket_t sock, uintptr_t userdata_sq, void *data, size_t len,
                         struct xlio_buf *buf)
{
    /* Create null-terminated string for message processing */
    char *msg = malloc(len + 1);
    if (!msg) {
        fprintf(stderr, "Failed to allocate memory for received message\n");
        g_state.api->xlio_socket_buf_free(sock, buf);
        return;
    }

    memcpy(msg, data, len);
    msg[len] = '\0';

    /* Remove trailing newline if present */
    if (len > 0 && msg[len - 1] == '\n') {
        msg[len - 1] = '\0';
        len--;
    }

    printf("Received: '%s' (socket userdata=%lx)\n", msg, userdata_sq);

    /* Process the message based on content */
    process_received_message(sock, msg, len);

    free(msg);

    /*
     * Return buffer to XLIO
     * ====================
     * This is required for proper zero-copy buffer management.
     */
    g_state.api->xlio_socket_buf_free(sock, buf);
}

/*
 * Accept callback (server only)
 * =============================
 * Called when a new connection is accepted on the listening socket.
 */
static void socket_accept_cb(xlio_socket_t sock, xlio_socket_t parent, uintptr_t parent_userdata_sq)
{
    int rc;

    printf("New connection accepted (parent userdata=%lx)\n", parent_userdata_sq);

    /* Store client socket for later cleanup */
    g_state.client_sock = sock;

    /* Update client socket userdata for identification */
    rc = g_state.api->xlio_socket_update(sock, 0, USERDATA_SERVER_CLIENT);
    if (rc != 0) {
        fprintf(stderr, "Failed to update client socket userdata\n");
    }

    /* Register TX buffer memory for server side connections */
    if (register_tx_buffer_pool(sock) != 0) {
        fprintf(stderr, "Failed to register TX buffer memory\n");
    }
}

/*
 * Utility Functions
 * ================
 */

/*
 * Send message using zero-copy operation with buffer pool
 * =======================================================
 * Gets a buffer from the pool, copies the message, and sends using zero-copy.
 * The buffer pointer is stored in userdata_op for identification in completion callback.
 */
static int send_message(xlio_socket_t sock, const char *msg)
{
    size_t len = strlen(msg);
    char *buffer;

    if (!g_state.mr_buf) {
        fprintf(stderr, "TX buffer pool not initialized\n");
        return -1;
    }

    if (len >= TX_BUFFER_SIZE) {
        fprintf(stderr, "Message too long for send buffer (max %d bytes)\n", TX_BUFFER_SIZE);
        return -1;
    }

    /* Get buffer from pool */
    buffer = get_tx_buffer();
    if (!buffer) {
        fprintf(stderr, "No available TX buffers in pool\n");
        return -1;
    }

    /* Copy message to the allocated buffer */
    memcpy(buffer, msg, len);

    /*
     * Configure send attributes for zero-copy operation
     * ================================================
     * Store the buffer pointer in userdata_op so we can return it to the pool
     * when the completion callback is invoked.
     */
    struct xlio_socket_send_attr send_attr = {
        .flags = XLIO_SOCKET_SEND_FLAG_FLUSH, /* Flush immediately */
        .mkey = g_state.mr_buf->lkey, /* Memory key for zero-copy */
        .userdata_op = (uintptr_t)buffer /* Buffer pointer for completion callback */
    };

    /*
     * Send data using XLIO Ultra API
     * ==============================
     */
    int rc = g_state.api->xlio_socket_send(sock, buffer, len, &send_attr);
    if (rc != 0) {
        fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
        /* Return buffer to pool on send failure */
        return_tx_buffer(buffer);
        return rc;
    }

    return 0;
}

/*
 * Send ping message with RTT timing
 * =================================
 * Records timestamp when sending ping for RTT measurement.
 */
static int send_ping_with_timing(xlio_socket_t sock)
{
    /* Record timestamp before sending ping */
    if (clock_gettime(CLOCK_MONOTONIC, &g_state.ping_sent_time) != 0) {
        fprintf(stderr, "Failed to get timestamp: %s\n", strerror(errno));
        return -1;
    }

    /* Send the ping message */
    return send_message(sock, MSG_PING);
}

/*
 * Calculate RTT in microseconds
 * =============================
 * Calculate round-trip time between two timespec timestamps.
 */
static double calculate_rtt_microseconds(const struct timespec *start, const struct timespec *end)
{
    long long start_ns = start->tv_sec * 1000000000LL + start->tv_nsec;
    long long end_ns = end->tv_sec * 1000000000LL + end->tv_nsec;
    long long diff_ns = end_ns - start_ns;

    return diff_ns / 1000.0;
}

/*
 * Process received message based on application logic
 * ===================================================
 */
static void process_received_message(xlio_socket_t sock, const char *msg, size_t len)
{
    if (strcmp(msg, MSG_PING) == 0) {
        /* Server: respond to ping with pong */
        printf("Responding with pong\n");
        send_message(sock, MSG_PONG);

    } else if (strcmp(msg, MSG_PONG) == 0) {
        /* Client: received pong, send next ping or exit */
        g_state.pongs_received++;

        /* Calculate and display RTT */
        struct timespec pong_received_time;
        if (clock_gettime(CLOCK_MONOTONIC, &pong_received_time) == 0) {
            double rtt_us =
                calculate_rtt_microseconds(&g_state.ping_sent_time, &pong_received_time);
            printf("Received pong #%d (RTT: %.3f µs)\n", g_state.pongs_received, rtt_us);
        } else {
            printf("Received pong #%d (RTT measurement failed)\n", g_state.pongs_received);
        }

        if (g_state.pings_sent < g_config.ping_count) {
            send_ping_with_timing(sock);
            g_state.pings_sent++;
            printf("Sent ping #%d\n", g_state.pings_sent);
        } else {
            printf("Ping-pong completed, sending exit message\n");
            send_message(sock, MSG_EXIT);

            /* Server won't respond to exit messages, so don't wait */
            printf("Exit message sent, client shutting down\n");
            g_state.quit = true;
        }

    } else if (strcmp(msg, MSG_EXIT) == 0) {
        printf("Exit message received, shutting down\n");
        g_state.quit = true;

    } else {
        printf("Unknown message: '%s'\n", msg);
    }
}

/*
 * Timeout signal handler
 * =====================
 * Called when SIGALRM is received after the specified timeout period.
 * Sets the quit flag to terminate the application gracefully.
 */
static void timeout_handler(int sig)
{
    (void)sig;
    printf("\nTimeout reached (%d seconds), terminating application\n", g_config.timeout_seconds);
    g_state.quit = true;
}

/*
 * Setup application timeout using SIGALRM
 * =======================================
 * Registers a signal handler for SIGALRM and sets an alarm to fire
 * after the specified number of seconds.
 */
static int setup_timeout(int timeout_seconds)
{
    struct sigaction sa;

    /* Setup signal handler */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        fprintf(stderr, "Failed to register SIGALRM handler: %s\n", strerror(errno));
        return -1;
    }

    /* Set the alarm */
    if (alarm(timeout_seconds) != 0) {
        printf("Warning: Previous alarm was overridden\n");
    }

    return 0;
}

/*
 * TX Buffer Pool Management Functions
 * ===================================
 *
 * TX buffer pool is an application logic, but is critical for performance.
 * An efficient TX buffer pool implementation can be complex and needs to take into
 * account hardware nuances, such as CPU caches, and application architecture, such as
 * multi-threading.
 *
 * Why Multiple TX Buffers Are Needed
 * ----------------------------------
 * Zero-copy send operations are asynchronous - the buffer cannot be reused immediately
 * after the send call returns. Application gives ownership to the XLIO stack until
 * the transmission completes, which is signaled via the completion callback.
 *
 * Although it is allowed to reuse a single buffer for static unchanged data, dynamic
 * data requires multiple buffers.
 *
 * Note, XLIO_SOCKET_SEND_FLAG_INLINE changes behavior of the send operation along with
 * its requirements and guarantees. Please refer to the XLIO Ultra API documentation
 * for more details.
 *
 * TX Buffer Lifecycle
 * ------------------
 * Typically, a buffer goes through the following states in its lifecycle:
 *
 * 1. POOL INITIALIZATION:
 *    - Memory allocation
 *    - This can be a pool of fixed-sized buffers or dynamically allocated buffers from
 *      a pre-allocated memory block
 *
 * 2. MEMORY REGISTRATION:
 *    - Memory registration of the underlying memory blocks
 *    - See memory registration section for more details
 *
 * 3. BUFFER ALLOCATION:
 *    - Application allocates buffers on demand
 *
 * 4. MESSAGE PREPARATION:
 *    - Application constructs the message withing the buffer
 *
 * 5. TRANSMISSION:
 *    - Application sends the message using the send operation
 *    - At this point, ownership on the buffer is transferred to the XLIO stack
 *
 * 6. COMPLETION:
 *    - After completing all the related operations, XLIO generates a completion event
 *    - Ownership on the buffer is transferred back to the application
 *    - XLIO doesn't make access to the buffer after the completion event
 *
 * 7. RETURN TO POOL:
 *    - Application returns the buffer to the TX buffer pool
 *    - The buffer is now available for reuse
 *
 * The states 1-2 are initialization and the states 3-7 repeat for each message.
 *
 * Memory registration
 * -------------------
 * Before sending zero-copy data, the application must register the memory. This is
 * done in advance due to the high cost of this operation.
 *
 * Memory registration pins pages in memory and allows hardware to translate userspace
 * logical addresses to physical addresses.
 *
 * XLIO Ultra API requires memory to be registered for its protection domain. Protection
 * domain is unique per device (network interface). It can determined for a socket once
 * the outgoing network device is set for the socket. Therefore, protection domain can
 * be obtained from a socket after the connect operation or after the accept callback
 * is called.
 *
 * For the same protection domain, memory registration should be performed only once.
 * For different protection domains, memory registration should be performed for each
 * protection domain and respective memory key (lkey) should be used in the send
 * operation.
 */

/*
 * Initialize TX buffer pool
 * ========================
 * Allocates memory block for all TX buffers and initializes the stack-based pool
 * with buffer pointers. This should be called once during application initialization,
 * before any sockets are created.
 */
static int init_tx_buffer_pool(void)
{
    size_t total_size = TX_BUFFER_COUNT * TX_BUFFER_SIZE;
    int i;

    /* Allocate memory block for all TX buffers */
    g_state.tx_buffers = malloc(total_size);
    if (!g_state.tx_buffers) {
        fprintf(stderr, "Failed to allocate TX buffer memory block\n");
        return -1;
    }

    /* Allocate stack array for buffer pointer tracking */
    g_state.pool_stack = malloc(TX_BUFFER_COUNT * sizeof(char *));
    if (!g_state.pool_stack) {
        fprintf(stderr, "Failed to allocate TX buffer pool stack\n");
        free(g_state.tx_buffers);
        g_state.tx_buffers = NULL;
        return -1;
    }

    /* Initialize stack with all buffer pointers */
    for (i = 0; i < TX_BUFFER_COUNT; i++) {
        g_state.pool_stack[i] = g_state.tx_buffers + (i * TX_BUFFER_SIZE);
    }
    g_state.pool_top = TX_BUFFER_COUNT - 1;

    printf("TX buffer pool initialized: %d buffers of %d bytes each (total %zu bytes)\n",
           TX_BUFFER_COUNT, TX_BUFFER_SIZE, total_size);

    return 0;
}

/*
 * Register TX buffer pool
 * =======================================
 * Registers the pre-allocated TX buffer memory block for zero-copy operations.
 * For simplicity, this example doesn't support multiple protection domains.
 */
static int register_tx_buffer_pool(xlio_socket_t sock)
{
    size_t total_size = TX_BUFFER_COUNT * TX_BUFFER_SIZE;

    /* Check if memory is already registered */
    if (g_state.mr_buf) {
        printf("TX buffer memory already registered, skipping re-registration\n");
        return 0;
    }

    /* Verify that buffer pool was initialized */
    if (!g_state.tx_buffers) {
        fprintf(stderr, "Cannot register TX buffers: pool not initialized\n");
        return -1;
    }

    /* Obtain protection domain from socket */
    if (!g_state.pd) {
        g_state.pd = g_state.api->xlio_socket_get_pd(sock);
        if (!g_state.pd) {
            fprintf(stderr,
                    "Cannot register TX buffers: failed to get protection domain from socket\n");
            return -1;
        }
    }

    /* Register the entire memory block */
    g_state.mr_buf = ibv_reg_mr(g_state.pd, g_state.tx_buffers, total_size, IBV_ACCESS_LOCAL_WRITE);
    if (!g_state.mr_buf) {
        fprintf(stderr, "Failed to register TX buffer memory\n");
        return -1;
    }

    printf("TX buffer memory registered\n");

    return 0;
}

/*
 * Get TX buffer from pool
 * ======================
 * Pops a buffer pointer from the stack and returns it.
 * Returns buffer pointer on success, NULL if pool is empty.
 */
static char *get_tx_buffer(void)
{
    char *buffer_ptr;

    /* Check if pool has available buffers */
    if (g_state.pool_top < 0) {
        return NULL;
    }

    /* Pop buffer pointer from stack */
    buffer_ptr = g_state.pool_stack[g_state.pool_top--];

    return buffer_ptr;
}

/*
 * Return TX buffer to pool
 * =======================
 * Returns a buffer pointer back to the TX buffer pool, making it available for reuse.
 */
static void return_tx_buffer(char *buffer_ptr)
{
    size_t offset;
    size_t total_size = TX_BUFFER_COUNT * TX_BUFFER_SIZE;

    /* Validate that buffer pointer belongs to our memory block */
    if (buffer_ptr < g_state.tx_buffers || buffer_ptr >= g_state.tx_buffers + total_size) {
        fprintf(stderr, "Invalid buffer pointer %p (not in memory block range %p-%p)\n",
                (void *)buffer_ptr, (void *)g_state.tx_buffers,
                (void *)(g_state.tx_buffers + total_size));
        return;
    }

    /* Validate that buffer pointer is properly aligned to buffer boundaries */
    offset = buffer_ptr - g_state.tx_buffers;
    if (offset % TX_BUFFER_SIZE != 0) {
        fprintf(stderr, "Invalid buffer pointer %p (not aligned to buffer boundary)\n",
                (void *)buffer_ptr);
        return;
    }

    /* Check for stack overflow */
    if (g_state.pool_top >= TX_BUFFER_COUNT - 1) {
        fprintf(stderr, "TX buffer pool stack overflow (double-free of buffer %p?)\n",
                (void *)buffer_ptr);
        return;
    }

    /* Push buffer pointer back onto stack */
    g_state.pool_stack[++g_state.pool_top] = buffer_ptr;
}

/*
 * Cleanup TX buffer pool
 * =====================
 * Deregisters memory and frees all allocated resources.
 */
static void cleanup_tx_buffer_pool(void)
{
    if (g_state.mr_buf) {
        ibv_dereg_mr(g_state.mr_buf);
        g_state.mr_buf = NULL;
    }

    if (g_state.tx_buffers) {
        free(g_state.tx_buffers);
        g_state.tx_buffers = NULL;
    }

    if (g_state.pool_stack) {
        free(g_state.pool_stack);
        g_state.pool_stack = NULL;
    }

    g_state.pool_top = -1;
}
