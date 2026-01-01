/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SEND_INFO
#define SEND_INFO

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "core/util/utils.h"
#include "core/event/event.h"
#include "core/proto/header.h"

class event;

class neigh_send_data {
public:
    neigh_send_data(iovec *iov, size_t sz, header *hdr, uint32_t mtu, uint32_t packet_id);

    neigh_send_data(neigh_send_data &&snd_data);

    virtual ~neigh_send_data();

    iovec m_iov;
    header *m_header;
    uint32_t m_mtu;
    uint32_t m_packet_id;
};

#endif /* SEND_INFO */
