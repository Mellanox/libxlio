/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "xlio_extra.h"

int main(void)
{
    struct xlio_api_t *api = xlio_get_api();
    if (!api) {
        fprintf(stderr, "XLIO_API_NOT_AVAILABLE\n");
        return 2;
    }

    struct xlio_init_attr attr;
    memset(&attr, 0, sizeof(attr));

    int rc = api->xlio_init_ex(&attr);
    if (rc != 0) {
        fprintf(stderr, "XLIO_INIT_EX_FAILED: rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
        return 1;
    }

    fprintf(stderr, "XLIO_INIT_EX_OK\n");
    api->xlio_exit();
    return 0;
}
