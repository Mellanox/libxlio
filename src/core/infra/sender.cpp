/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/infra/sender.h"

neigh_send_data::neigh_send_data(iovec *iov, size_t sz, header *hdr, uint32_t mtu,
                                 uint32_t packet_id)
    : m_header(hdr->copy())
    , m_mtu(mtu)
    , m_packet_id(packet_id)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!iov || sz == 0U) {
        m_iov.iov_base = nullptr;
        m_iov.iov_len = 0;
        return;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    uint8_t *buff = nullptr;
    size_t total_len = 0;

    for (uint32_t i = 0; i < sz; i++) {
        total_len += iov[i].iov_len;
    }

    buff = new uint8_t[total_len];
    BULLSEYE_EXCLUDE_BLOCK_START
    if (!buff) {
        m_iov.iov_base = nullptr;
        m_iov.iov_len = 0;
        return;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    memcpy_fromiovec(buff, iov, sz, 0, total_len);
    m_iov.iov_base = buff;
    m_iov.iov_len = total_len;
}

neigh_send_data::neigh_send_data(neigh_send_data &&snd_data)
{
    m_header = snd_data.m_header;
    snd_data.m_header = nullptr;

    m_iov = snd_data.m_iov;
    snd_data.m_iov.iov_base = nullptr;
    snd_data.m_iov.iov_len = 0U;

    m_mtu = snd_data.m_mtu;
    m_packet_id = snd_data.m_packet_id;
}

neigh_send_data::~neigh_send_data()
{
    if (m_iov.iov_base) {
        delete[] ((uint8_t *)m_iov.iov_base);
    }

    if (m_header) {
        delete m_header;
    }
}
