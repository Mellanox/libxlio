/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <mellanox/xlio_extra.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif /* ARRAY_SIZE */

#define HELLO_MSG "Hello"

static struct xlio_api_t *xlio_api = NULL;

static void server(const char *server_ip)
{
    char buf[64];
    struct sockaddr_in addr;
    ssize_t len;
    int sock;
    int sock2;
    int sock3;
    int sock_in;
    int sock_in2;
    int val = SO_XLIO_ISOLATE_SAFE;
    int rc;

    /*
     * Socket create
     */

    sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock >= 0);
    sock2 = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock2 >= 0);
    sock3 = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock3 >= 0);

    rc = setsockopt(sock, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
    assert(rc == 0);

    /*
     * Socket bind
     */

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(server_ip);
    addr.sin_port = htons(8080);

    rc = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    addr.sin_port = htons(8081);
    rc = bind(sock2, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    addr.sin_port = htons(8082);
    rc = bind(sock3, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    rc = setsockopt(sock2, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
    assert(rc == 0);

    /*
     * Socket listen
     */

    rc = listen(sock, 5);
    assert(rc == 0);

    rc = listen(sock2, 5);
    assert(rc == 0);

    rc = listen(sock3, 5);
    assert(rc == 0);

    rc = setsockopt(sock3, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
    assert(rc == -1);
    assert(errno == EINVAL);

    /*
     * Socket accept
     */

    do {
        sock_in = accept(sock, NULL, NULL);
    } while (sock_in == -1 && errno == EINTR);
    assert(sock_in >= 0);

    do {
        sock_in2 = accept(sock2, NULL, NULL);
    } while (sock_in2 == -1 && errno == EINTR);
    assert(sock_in2 >= 0);

    /*
     * Socket read / write
     */

    len = write(sock_in, HELLO_MSG, sizeof(HELLO_MSG));
    assert(len > 0);

    do {
        len = read(sock_in, buf, sizeof(buf));
    } while (len == -1 && errno == EINTR);
    assert(len > 0);
    assert(len == sizeof(HELLO_MSG));
    assert(strncmp(buf, HELLO_MSG, strlen(HELLO_MSG)) == 0);

    /*
     * Socket close
     */

    sleep(1);

    rc = close(sock_in);
    assert(rc == 0);
    rc = close(sock_in2);
    assert(rc == 0);
    rc = close(sock);
    assert(rc == 0);
    rc = close(sock2);
    assert(rc == 0);
    rc = close(sock3);
    assert(rc == 0);
}

static void client(const char *server_ip)
{
    char buf[64];
    struct sockaddr_in addr;
    ssize_t len;
    int sock;
    int sock2;
    int val = SO_XLIO_ISOLATE_SAFE;
    int valdef = SO_XLIO_ISOLATE_DEFAULT;
    int rc;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock >= 0);
    sock2 = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock2 >= 0);

    rc = setsockopt(sock, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
    assert(rc == 0);
    rc = setsockopt(sock, SOL_SOCKET, SO_XLIO_ISOLATE, &valdef, sizeof(valdef));
    assert(rc == -1);
    assert(errno == EINVAL);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(server_ip);
    addr.sin_port = htons(8080);

    rc = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    addr.sin_port = htons(8081);
    rc = connect(sock2, (struct sockaddr *)&addr, sizeof(addr));
    assert(rc == 0);

    rc = setsockopt(sock2, SOL_SOCKET, SO_XLIO_ISOLATE, &val, sizeof(val));
    assert(rc == -1);
    assert(errno == EINVAL);

    len = write(sock, HELLO_MSG, sizeof(HELLO_MSG));
    assert(len > 0);

    do {
        len = read(sock, buf, sizeof(buf));
    } while (len == -1 && errno == EINTR);
    assert(len > 0);
    assert(len == sizeof(HELLO_MSG));
    assert(strncmp(buf, HELLO_MSG, strlen(HELLO_MSG)) == 0);

    sleep(1);

    rc = close(sock);
    assert(rc == 0);
    rc = close(sock2);
    assert(rc == 0);
}

static void usage(const char *name)
{
    printf("Usage: %s <-s|-c> <server-ip>\n", name);
    printf(" -s         server mode\n");
    printf(" -c         client mode\n");
    printf(" server-ip  IPv4 address to listen/connect to\n");
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        usage(argc > 0 ? argv[0] : "a.out");
    }

    xlio_api = xlio_get_api();
    if (xlio_api == NULL) {
        printf("Extra API not found. Run under XLIO.\n");
        return 1;
    }

    if (strcmp(argv[1], "-s") == 0) {
        server(argv[2]);
    } else if (strcmp(argv[1], "-c") == 0) {
        client(argv[2]);
    } else {
        usage(argv[0]);
    }

    printf("Success.\n");
    return 0;
}
