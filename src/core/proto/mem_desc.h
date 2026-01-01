/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _MEM_DESC_H
#define _MEM_DESC_H

#include <stdint.h>

/* forward declarations */
class ib_ctx_handler;
class mem_buf_desc_t;

class mem_desc {
public:
    virtual ~mem_desc() {}

    /* get() is always called under socket lock */
    virtual void get(void) = 0;
    /*
     * There is no guarantee that put() is protected by either
     * socket or ring lock
     */
    virtual void put(void) = 0;

    /* get_lkey() is always called under socket lock */
    virtual uint32_t get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, const void *addr,
                              size_t len)
    {
        NOT_IN_USE(desc);
        NOT_IN_USE(ib_ctx);
        NOT_IN_USE(addr);
        NOT_IN_USE(len);
        return LKEY_ERROR;
    }
};

#endif /* _MEM_DESC_H */
