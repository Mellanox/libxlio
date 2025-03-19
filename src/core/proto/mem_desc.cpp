/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
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
