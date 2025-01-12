/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _MEM_DESC_H
#define _MEM_DESC_H

#include <stdint.h>
#include <util/vtypes.h>

/*
 * Note, the following mem_desc implementations must be allocated with new()
 * (not by new[], nor by placement new, nor a local object on the stack,
 * nor a namespace-scope / global, nor a member of another object; but by
 * plain ordinary new):
 *  - zcopy_user_memory
 *  - zcopy_external
 * This is because they call "delete this" in put() method.
 */

class ib_ctx_handler;
class mem_buf_desc_t;

class mem_desc {
public:
    virtual ~mem_desc() {}

    /* get() is always called under socket lock */
    virtual void get() = 0;
    /*
     * There is no guarantee that put() is protected by either
     * socket or ring lock
     */
    virtual void put() = 0;

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
