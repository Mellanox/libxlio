/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "xlio_extra.h"

static void dummy_event_cb(xlio_socket_t s, uintptr_t ud, int ev, int val)
{
    (void)s;
    (void)ud;
    (void)ev;
    (void)val;
}

int main(void)
{
    struct xlio_api_t *api = xlio_get_api();
    if (!api) {
        fprintf(stderr, "XLIO_API_NOT_AVAILABLE\n");
        return 2;
    }

    struct xlio_poll_group_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.socket_event_cb = dummy_event_cb;

    xlio_poll_group_t group = 0;
    int rc = api->xlio_poll_group_create(&attr, &group);

    if (rc != 0) {
        fprintf(stderr, "POLL_GROUP_CREATE_FAILED: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    fprintf(stderr, "POLL_GROUP_CREATE_OK\n");
    api->xlio_poll_group_destroy(group);
    return 0;
}
