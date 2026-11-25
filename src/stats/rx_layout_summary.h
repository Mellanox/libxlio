/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef XLIO_RX_LAYOUT_SUMMARY_H
#define XLIO_RX_LAYOUT_SUMMARY_H
#include "core/util/rx_layout_capture.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
namespace xlio_rx_layout {
inline uint16_t u16(const uint8_t *p)
{
    return (uint16_t(p[0]) << 8) | p[1];
}
inline uint32_t u32(const uint8_t *p)
{
    return (uint32_t(u16(p)) << 16) | u16(p + 2);
}
inline uint64_t u64(const uint8_t *p)
{
    return (uint64_t(u32(p)) << 32) | u32(p + 4);
}
inline std::string hex_bytes(const uint8_t *p, size_t n)
{
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        out << std::setw(2) << unsigned(p[i]);
    }
    return out.str();
}
struct layout {
    uint32_t frame_bytes = 0, payload_bytes = 0, payload_offset = 0;
    uint16_t l2_bytes = 0, l3_bytes = 0, tcp_bytes = 0, lro_segments = 0;
    uint8_t payload_mod64 = 0, striding = 0, tcp_flags = 0, ip_version = 0;
};
struct observation {
    layout sizes;
    std::string excluded, tuple, disq, options;
    uint64_t flow_id = 0;
    uint32_t seq = 0, expected = 0, tsval = 0, tsecr = 0;
    bool expected_valid = false, tcp_valid = false, ip_valid = false;
    bool timestamp = false, options_valid = true;
    uint8_t ecn = 0, abrt = 0;
    bool cqe_valid = false, ethernet_valid = false, tcp_fields_valid = false, incomplete = false;
    int lro_psh = -1, lro_timestamp_valid = -1;
    bool lro_ack_valid = false;
    std::string timestamp_change = "-", ack_change = "-", window_change = "-";
    std::string option_profile = "unknown";
};
inline const char *abort_reason_name(unsigned reason)
{
    const char *names[] = {"0:max-size", "1:timeout", "2:exception", "3:Other"};
    return names[reason & 3];
}
inline std::string abort_name(const record &r)
{
    if (!r.cqe_valid || !r.cqe[32]) {
        return "-";
    }
    return abort_reason_name((r.cqe[4] >> 4) & 3);
}
inline observation decode(const record &r)
{
    observation o;
    o.cqe_valid = r.cqe_valid;
    o.incomplete = r.incomplete;
    o.ethernet_valid = r.eth_len >= 14 && r.eth_len <= sizeof(r.ethernet);
    o.tcp_fields_valid = r.tcp_len >= 20 && r.tcp_len <= sizeof(r.tcp);
    auto &s = o.sizes;
    s.frame_bytes = r.frame_bytes;
    s.striding = r.striding;
    s.lro_segments = r.cqe_valid ? r.cqe[32] : 0;
    if (s.lro_segments) {
        o.lro_psh = (r.cqe[4] >> 6) & 1;
        o.lro_timestamp_valid = (r.cqe[4] >> 7) & 1;
        unsigned l4_type = (r.cqe[29] >> 4) & 7;
        o.lro_ack_valid = l4_type == 3 || l4_type == 4;
    }
    o.abrt = (r.cqe[4] >> 4) & 3;
    if (r.eth_len < 14 || r.eth_len > sizeof(r.ethernet)) {
        o.excluded = "truncated Ethernet";
        return o;
    }
    s.l2_bytes = r.eth_len;
    uint16_t type = u16(r.ethernet + r.eth_len - 2);
    uint32_t ip_bytes = 0;
    bool fragment = false;
    if (type == 0x800 && r.ip_len >= 20 && r.ip[0] >> 4 == 4) {
        o.ip_valid = true;
        s.ip_version = 4;
        ip_bytes = u16(r.ip + 2);
        fragment = u16(r.ip + 6) & 0x3fffU;
        o.ecn = r.ip[1] & 3;
    } else if (type == 0x86dd && r.ip_len >= 40 && r.ip[0] >> 4 == 6) {
        o.ip_valid = true;
        s.ip_version = 6;
        ip_bytes = 40U + u16(r.ip + 4);
        o.ecn = (r.ip[1] >> 4) & 3;
        for (unsigned i = 0; i < std::min<size_t>(r.ext_count, sizeof(r.extensions)); ++i) {
            fragment |= r.extensions[i] == 44;
        }
    } else {
        o.excluded = type <= 1500 ? "LLC/SNAP" : r.ip_len ? "invalid IP" : "non-IP or truncated IP";
        return o;
    }
    s.l3_bytes = r.l3_bytes;
    if (r.tcp_len < 20 || r.tcp_len > sizeof(r.tcp)) {
        o.excluded = fragment ? "IP fragment" : "non-TCP or incomplete TCP";
        return o;
    }
    s.tcp_bytes = (r.tcp[12] >> 4) * 4U;
    s.tcp_flags = r.tcp[13];
    s.payload_offset = s.l2_bytes + s.l3_bytes + s.tcp_bytes;
    s.payload_mod64 = (r.frame_mod64 + s.l2_bytes + s.l3_bytes + s.tcp_bytes) % 64;
    uint32_t header = s.l2_bytes + s.l3_bytes + s.tcp_bytes;
    uint32_t logical_frame = s.lro_segments > 1 ? r.frame_bytes : s.l2_bytes + ip_bytes;
    if (s.tcp_bytes < 20 || s.tcp_bytes != r.tcp_len ||
        s.l3_bytes < (s.ip_version == 4 ? 20 : 40) || header > logical_frame ||
        logical_frame > r.frame_bytes) {
        o.excluded = "invalid header lengths";
        return o;
    }
    if (!r.cqe_valid) {
        o.excluded = "CQE unavailable";
        return o;
    }
    s.payload_bytes = logical_frame - header;
    o.tcp_valid = true;
    o.seq = u32(r.tcp + 4);
    if (fragment) {
        o.excluded = "IP fragment";
    }
    bool sack = false;
    for (unsigned i = 20; i < r.tcp_len;) {
        uint8_t kind = r.tcp[i];
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            ++i;
            continue;
        }
        if (i + 1 >= r.tcp_len || r.tcp[i + 1] < 2 || i + r.tcp[i + 1] > r.tcp_len) {
            o.options_valid = false;
            break;
        }
        if (kind == 8 && (r.tcp[i + 1] != 10 || i + 10 > sizeof(r.tcp) || o.timestamp)) {
            o.options_valid = false;
            break;
        }
        if (kind == 5 && (r.tcp[i + 1] < 10 || (r.tcp[i + 1] - 2) % 8)) {
            o.options_valid = false;
            break;
        }
        if (kind == 8) {
            o.timestamp = true;
            o.tsval = u32(r.tcp + i + 2);
            o.tsecr = u32(r.tcp + i + 6);
        } else {
            sack |= kind == 5;
            if (!o.options.empty()) {
                o.options += "/";
            }
            o.options += std::to_string(kind);
        }
        i += r.tcp[i + 1];
    }
    o.option_profile = !o.options_valid ? "malformed"
        : sack                          ? "SACK"
        : !o.options.empty()            ? "other"
        : o.timestamp                   ? "timestamp-only"
                                        : "none";
    if (s.lro_segments) {
        if (!o.options_valid) {
            o.timestamp_change = "malformed";
        } else if (!o.timestamp) {
            o.timestamp_change = o.lro_timestamp_valid ? "final-only" : "none";
        } else if (!o.lro_timestamp_valid) {
            o.timestamp_change = "first-only";
        } else {
            bool changed = o.tsval != u32(r.cqe + 48);
            if ((r.tcp[13] & 0x10) && o.lro_ack_valid) {
                changed |= o.tsecr != u32(r.cqe + 52);
            }
            o.timestamp_change = changed ? "changed" : "same";
        }
        auto first_window = u16(r.tcp + 14), last_window = u16(r.cqe + 6);
        o.window_change = !last_window    ? "zero"
            : first_window == last_window ? "same"
            : last_window > first_window  ? "increased"
                                          : "decreased";
        if (o.lro_ack_valid) {
            uint32_t delta = u32(r.cqe + 8) - u32(r.tcp + 8);
            o.ack_change = !(r.tcp[13] & 0x10) ? "first-unset"
                : !delta                       ? "same"
                : delta == 0x80000000U         ? "ambiguous"
                : delta < 0x80000000U          ? "advanced"
                                               : "regressed";
        }
    }
    return o;
}

inline std::string sequence_relation(const observation &o)
{
    if (!o.expected_valid) {
        return "unknown";
    }
    uint32_t delta = o.seq - o.expected;
    return !delta              ? "contiguous"
        : delta == 0x80000000U ? "unknown"
        : delta < 0x80000000U  ? "forward-gap"
                               : "overlap";
}
inline std::string flow_tuple(const record &r, const observation &o, uint32_t ifindex)
{
    if (!o.tcp_valid) {
        return {};
    }
    char src[INET6_ADDRSTRLEN] {}, dst[INET6_ADDRSTRLEN] {};
    bool v4 = o.sizes.ip_version == 4;
    inet_ntop(v4 ? AF_INET : AF_INET6, r.ip + (v4 ? 12 : 8), src, sizeof(src));
    inet_ntop(v4 ? AF_INET : AF_INET6, r.ip + (v4 ? 16 : 24), dst, sizeof(dst));
    std::ostringstream out;
    out << "if=" << ifindex << " [" << src << "]:" << u16(r.tcp) << ">[" << dst
        << "]:" << u16(r.tcp + 2);
    for (unsigned pos = 12; pos + 6 <= r.eth_len; pos += 4) {
        out << " vlan=" << std::hex << u16(r.ethernet + pos) << ':'
            << (u16(r.ethernet + pos + 2) & 0xfff);
    }
    if (r.cqe_valid && (r.cqe[29] & 1)) {
        out << " cvlan=" << (u16(r.cqe + 30) & 0xfff);
    }
    return out.str();
}
class analyzer {
    struct flow {
        uint64_t id = 0, batch_id = 0, ring = 0, generation = 0, touched = 0;
        uint32_t next_seq = 0, tsval = 0;
        bool valid = false, timestamp = false;
        uint8_t ecn = 0, tcp_ecn = 0;
        std::string ip_key;
    };
    std::map<std::string, flow> flows;
    uint64_t next_id = 1, tick = 0;
    size_t limit;

public:
    explicit analyzer(size_t maximum = 4096)
        : limit(std::max(size_t(1), maximum))
    {
    }
    observation inspect(const record &r, const batch &b, uint64_t batch_id)
    {
        observation o = decode(r);
        o.incomplete |= !b.context.caps_known || !b.context.tir_known;
        o.tuple = flow_tuple(r, o, b.if_index);
        std::vector<std::string> why;
        auto reason = [&](const std::string &s) { why.push_back(s); };
        auto &c = b.context;
        if (c.tir_known && o.ip_valid && !(c.enable_mask & (o.sizes.ip_version == 4 ? 1 : 2))) {
            reason("LRO disabled");
        }
        if (r.cqe_valid) {
            if (!(r.cqe[28] & 1)) {
                reason("L2 not validated");
            }
            if (!(r.cqe[28] & 2)) {
                reason("L3 not validated");
            }
            if (!(r.cqe[28] & 4)) {
                reason("L4 not validated");
            }
            if (r.cqe[29] & 0x80) {
                reason("CQE IP fragment");
            }
            if (r.cqe[29] & 2) {
                reason("CQE IP options/extensions");
            }
        }
        if (o.ip_valid) {
            if (o.sizes.ip_version == 4 && (r.ip[0] & 15) > 5) {
                reason("IPv4 options");
            }
            if (r.ext_count) {
                reason("IPv6 extensions");
            }
        }
        if (!o.excluded.empty()) {
            reason(o.excluded);
        }
        if (o.tcp_valid) {
            const char *flag_names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
            for (unsigned bit : {0U, 1U, 2U, 5U}) {
                if (r.tcp[13] & (1U << bit)) {
                    reason(flag_names[bit]);
                }
            }
            if (r.tcp[12] & 1) {
                reason("NS");
            }
            if (r.tcp[12] & 14) {
                reason("reserved TCP flags");
            }
            if (c.caps_known && !c.psh && (r.tcp[13] & 8)) {
                reason("PSH unsupported");
            }
            if (c.caps_known && o.sizes.payload_bytes < c.min_mss) {
                reason("payload below min MSS");
            }
            if (!o.sizes.payload_bytes) {
                reason("no TCP payload");
            }
            if (!o.options_valid) {
                reason("malformed TCP options");
            }
            if (!o.options.empty()) {
                reason("TCP options " + o.options);
            }
            if (c.caps_known && !c.timestamp && o.timestamp) {
                reason("timestamp unsupported");
            }
        }
        // Compare only observations inside this reader batch and this ring generation.
        // Unknown/excluded packets may belong to any flow, so invalidate continuity.
        if (o.tuple.empty()) {
            for (auto &entry : flows) {
                if (entry.second.ring == b.ring_id) {
                    entry.second.valid = false;
                }
            }
        } else {
            auto found = flows.find(o.tuple);
            if (found == flows.end()) {
                if (flows.size() == limit) {
                    auto oldest = std::min_element(flows.begin(), flows.end(),
                                                   [](const auto &a, const auto &z) {
                                                       return a.second.touched < z.second.touched;
                                                   });
                    flows.erase(oldest);
                }
                found = flows.emplace(o.tuple, flow {}).first;
                found->second.id = next_id++;
            }
            auto &f = found->second;
            o.flow_id = f.id;
            o.expected_valid = o.excluded.empty() && f.valid && f.batch_id == batch_id &&
                f.ring == b.ring_id && f.generation == b.generation && !(r.tcp[13] & 2);
            o.expected = f.next_seq;
            std::string ip_key;
            if (o.sizes.ip_version == 4) {
                ip_key = hex_bytes(r.ip, 2) + hex_bytes(r.ip + 6, 2) + hex_bytes(r.ip + 9, 1);
            } else {
                ip_key = hex_bytes(r.ip, 4) + hex_bytes(r.ip + 6, 1);
            }
            if (o.expected_valid) {
                if (o.seq != o.expected) {
                    reason("observed sequence mismatch");
                }
                if (o.ecn != f.ecn || (r.tcp[13] & 0xc0) != f.tcp_ecn) {
                    reason("observed ECN change");
                }
                if (o.options_valid) {
                    if (o.timestamp != f.timestamp) {
                        reason("observed timestamp presence change");
                    } else if (o.timestamp && int32_t(o.tsval - f.tsval) < 0) {
                        reason("observed timestamp decrease");
                    }
                }
                if (ip_key != f.ip_key) {
                    reason("observed IP header change");
                }
            }
            f.touched = ++tick;
            f.batch_id = batch_id;
            f.ring = b.ring_id;
            f.generation = b.generation;
            f.next_seq = o.seq + o.sizes.payload_bytes + !!(r.tcp[13] & 2) + !!(r.tcp[13] & 1);
            f.timestamp = o.timestamp;
            f.tsval = o.tsval;
            // For an LRO completion, a valid CQE timestamp describes the final
            // coalesced segment; the in-memory option belongs to the first one.
            if (o.sizes.lro_segments && r.cqe_valid && (r.cqe[4] & 0x80)) {
                f.tsval = u32(r.cqe + 48);
            }
            f.ecn = o.ecn;
            f.tcp_ecn = r.tcp[13] & 0xc0;
            f.ip_key = std::move(ip_key);
            f.valid =
                o.excluded.empty() && !r.incomplete && o.options_valid && !(r.tcp[13] & (1 | 4));
        }
        if (!r.cqe_valid) {
            o.disq = "unknown";
        } else if (o.sizes.lro_segments) {
            o.disq = "-";
        } else if (why.empty()) {
            o.disq = "unknown";
        } else {
            for (const auto &s : why) {
                if (!o.disq.empty()) {
                    o.disq += "; ";
                }
                o.disq += s;
            }
        }
        return o;
    }
};
struct row {
    observation item;
    unsigned count = 0;
};
struct summary {
    std::vector<row> rows, excluded;
    unsigned data = 0, control = 0, offset64 = 0, address64 = 0, length64 = 0;
};
inline auto layout_key(const observation &o)
{
    const auto &r = o.sizes;
    return std::make_tuple(r.frame_bytes, r.payload_bytes, r.payload_offset, r.l2_bytes, r.l3_bytes,
                           r.tcp_bytes, r.lro_segments, r.payload_mod64, r.striding, r.tcp_flags,
                           r.ip_version, r.lro_segments ? o.abrt : 0, o.disq, o.excluded,
                           o.cqe_valid, o.ethernet_valid, o.tcp_fields_valid, o.incomplete,
                           o.lro_psh, o.lro_timestamp_valid, o.timestamp_change, o.ack_change,
                           o.window_change);
}
inline summary summarize(const std::vector<observation> &observations)
{
    summary result;
    std::map<decltype(layout_key(std::declval<const observation &>())), row> histogram;
    for (const auto &o : observations) {
        auto entry = histogram.emplace(layout_key(o), row {o, 0});
        ++entry.first->second.count;
        if (!o.excluded.empty()) {
            continue;
        }
        const auto &r = o.sizes;
        if (r.payload_bytes) {
            ++result.data;
            result.offset64 += r.payload_offset == 64;
            result.address64 += r.payload_mod64 == 0;
            result.length64 += r.payload_bytes % 64 == 0;
        } else {
            ++result.control;
        }
    }
    for (const auto &item : histogram) {
        (item.second.item.excluded.empty() ? result.rows : result.excluded).push_back(item.second);
    }
    for (auto *v : {&result.rows, &result.excluded}) {
        std::sort(v->begin(), v->end(), [](const row &a, const row &b) {
            return a.count != b.count ? a.count > b.count : layout_key(a.item) < layout_key(b.item);
        });
    }
    return result;
}
inline std::string progress_text(unsigned count, unsigned requested)
{
    if (count == 0) {
        return "No traffic";
    }
    return "Collecting samples (" + std::to_string(count) + "/" + std::to_string(requested) + ")";
}
} // namespace xlio_rx_layout
#endif
