/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TX_CALL_CTX_H
#define TX_CALL_CTX_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "proto/dst_entry.h"

/*
 * Own the sendmsg() metadata that must outlive the application call while its payload is
 * waiting in the worker queue. Each TX job carries its own copy, so a job never depends on
 * the lifetime of the originating call or of a sibling job.
 */
class tx_call_ctx {
public:
    tx_call_ctx() = default;

    tx_call_ctx(tx_call_t opcode, int flags, const void *control, size_t controllen)
        : m_opcode(opcode)
        , m_flags(flags)
    {
        if (controllen != 0U) {
            const uint8_t *data = static_cast<const uint8_t *>(control);
            m_control.assign(data, data + controllen);
        }
    }

    tx_call_t get_opcode() const { return m_opcode; }
    int get_flags() const { return m_flags; }
    const void *get_control() const { return m_control.data(); }
    size_t get_controllen() const { return m_control.size(); }

private:
    tx_call_t m_opcode = TX_UNDEF;
    int m_flags = 0;
    std::vector<uint8_t> m_control;
};

#endif // TX_CALL_CTX_H
