/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "core/dev/ib_ctx_handler.h"
#include "core/proto/mem_desc.h"
#include "core/util/sys_vars.h"

uint32_t zcopy_hugepage::get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, const void *addr,
                                  size_t len)
{
    NOT_IN_USE(desc);
    NOT_IN_USE(addr);
    NOT_IN_USE(len);

    if (unlikely(!m_is_pinned)) {
        lock();
        if (!m_is_pinned) {
            m_lkey = ib_ctx->user_mem_reg(m_addr, m_size, XLIO_IBV_ACCESS_LOCAL_WRITE);
            m_is_pinned = true;
        }
        unlock();
    }
    return m_lkey;
}

zcopy_hugepage_mgr::zcopy_hugepage_mgr()
{
    m_hugepage_size = safe_mce_sys().user_huge_page_size;
    m_hugepage_mask = ~((uintptr_t)m_hugepage_size - 1);
}
