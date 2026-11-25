/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef XLIO_RX_LAYOUT_SAMPLE_H
#define XLIO_RX_LAYOUT_SAMPLE_H
#include "util/rx_layout_capture.h"
#include <algorithm>
#include <cstring>
#include <time.h>
namespace xlio_rx_layout {
inline uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t(p[0]) << 8) | p[1];
}
// Locate and copy only bounded, requested headers. Classification and analysis
// belong to xlio_stats. Every packet completion occupies one record, even when
// these headers cannot be located. Fillers/error CQEs are not packet completions.
inline record collect_headers(const uint8_t *frame, size_t bytes, bool striding, const void *cqe)
{
    record r {};
    r.incomplete = cqe == nullptr;
    r.striding = striding;
    if (cqe) {
        std::memcpy(r.cqe, cqe, sizeof(r.cqe));
        r.cqe_valid = 1;
    }
    if (!frame || bytes > UINT32_MAX) {
        r.incomplete = 1;
        return r;
    }
    r.frame_bytes = bytes;
    r.frame_mod64 = uintptr_t(frame) & 63U;
    auto copy = [&](uint8_t *dst, size_t offset, size_t wanted) -> uint8_t {
        size_t n = offset < bytes ? std::min(wanted, bytes - offset) : 0;
        if (n) {
            std::memcpy(dst, frame + offset, n);
        }
        if (n < wanted) {
            r.incomplete = 1;
        }
        return n;
    };
    r.eth_len = copy(r.ethernet, 0, 14);
    if (r.eth_len < 14) {
        return r;
    }
    uint16_t type = read_be16(r.ethernet + 12);
    size_t l2 = 14;
    while (type == 0x8100 || type == 0x88a8) {
        if (l2 + 4 > sizeof(r.ethernet)) {
            r.incomplete = 1;
            return r;
        }
        r.eth_len += copy(r.ethernet + l2, l2, 4);
        if (r.eth_len < l2 + 4) {
            return r;
        }
        type = read_be16(r.ethernet + l2 + 2);
        l2 += 4;
    }
    uint8_t protocol;
    size_t ip_end;
    if (type == 0x0800) {
        r.ip_len = copy(r.ip, l2, 20);
        if (r.ip_len < 20) {
            return r;
        }
        r.l3_bytes = (r.ip[0] & 15U) * 4U;
        ip_end = l2 + read_be16(r.ip + 2);
        protocol = r.ip[9];
        if (r.ip[0] >> 4 != 4 || r.l3_bytes < 20 || ip_end < l2 + r.l3_bytes) {
            r.incomplete = 1;
            return r;
        }
        // IPv4 option bodies are deliberately not copied.
        r.incomplete |= r.l3_bytes > 20;
        if (read_be16(r.ip + 6) & 0x1fffU) {
            return r; // A non-first fragment has no TCP header at this offset.
        }
    } else if (type == 0x86dd) {
        r.ip_len = copy(r.ip, l2, 40);
        if (r.ip_len < 40) {
            return r;
        }
        r.l3_bytes = 40;
        ip_end = l2 + 40U + read_be16(r.ip + 4);
        protocol = r.ip[6];
        if (r.ip[0] >> 4 != 6 || !read_be16(r.ip + 4)) {
            r.incomplete = 1;
            return r;
        }
        while (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 51 ||
               protocol == 44) {
            r.incomplete = 1; // Extension bodies are not recorded.
            size_t pos = l2 + r.l3_bytes;
            if (r.ext_count == sizeof(r.extensions) || pos + 2 > std::min(bytes, ip_end)) {
                return r;
            }
            r.extensions[r.ext_count++] = protocol;
            size_t len = protocol == 44 ? 8
                : protocol == 51        ? (size_t(frame[pos + 1]) + 2) * 4
                                        : (size_t(frame[pos + 1]) + 1) * 8;
            if (pos + len > std::min(bytes, ip_end) || r.l3_bytes + len > UINT16_MAX) {
                return r;
            }
            if (protocol == 44 && (read_be16(frame + pos + 2) & 0xfff8U)) {
                return r;
            }
            protocol = frame[pos];
            r.l3_bytes += len;
        }
    } else {
        // No application payload or unrelated protocol header is requested.
        return r;
    }
    if (protocol != 6) {
        return r;
    }
    size_t tcp_start = l2 + r.l3_bytes;
    size_t limit = (r.cqe_valid && r.cqe[32] > 1) ? bytes : std::min(bytes, ip_end);
    if (ip_end > bytes || tcp_start + 20 > limit) {
        r.incomplete = 1;
        return r;
    }
    r.tcp_len = copy(r.tcp, tcp_start, 20);
    unsigned tcp_bytes = (r.tcp[12] >> 4) * 4U;
    if (tcp_bytes < 20 || tcp_start + tcp_bytes > limit) {
        r.incomplete = 1;
        return r;
    }
    r.tcp_len += copy(r.tcp + 20, tcp_start + 20, tcp_bytes - 20);
    return r;
}
inline void capture_sample(slot *s, const uint8_t *frame, size_t bytes, bool striding,
                           const void *cqe, const receive_context &context)
{
    if (!s) {
        return;
    }
    auto token = begin(*s);
    if (!token) {
        return;
    }
    struct timespec now {};
    const bool timed = clock_gettime(CLOCK_MONOTONIC_RAW, &now) == 0;
    record sample = collect_headers(frame, bytes, striding, cqe);
    sample.sw_time_ns = timed ? uint64_t(now.tv_sec) * 1000000000ULL + now.tv_nsec : 0;
    sample.incomplete |= !timed;
    // This metadata is protected by the same producer/reader ownership handoff.
    if (!captured(token)) {
        s->context = context;
    }
    publish_attempt(*s, token, &sample);
}
} // namespace xlio_rx_layout
#endif
