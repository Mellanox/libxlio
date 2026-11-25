/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef XLIO_RX_ANALYSIS_CSV_H
#define XLIO_RX_ANALYSIS_CSV_H
#include "rx_layout_summary.h"
#include <ostream>
namespace xlio_rx_layout {
inline void csv_line(std::ostream &out, const std::vector<std::string> &fields)
{
    bool first = true;
    for (const auto &field : fields) {
        if (!first) {
            out << ',';
        }
        first = false;
        out << '"';
        for (char c : field) {
            if (c == '"') {
                out << '"';
            }
            out << c;
        }
        out << '"';
    }
    out << '\n';
}
inline void csv_header(std::ostream &out)
{
    csv_line(out,
             {"batch",
              "ring-id",
              "ring-generation",
              "ifindex",
              "flow-id",
              "tuple",
              "expected-seqno",
              "sw-time-ns",
              "incomplete",
              "excluded",
              "rq",
              "frame-bytes",
              "frame-address-mod64",
              "l2-bytes",
              "ip-bytes",
              "tcp-bytes",
              "payload-bytes",
              "payload-offset",
              "payload-address-mod64",
              "payload-length-mod64",
              "LRO",
              "lro_abrt",
              "lro disq",
              "ethernet-header",
              "ip-header",
              "ipv6-extension-types",
              "tcp-header",
              "tcp-options",
              "ip-version",
              "ip-dscp-ecn",
              "ipv4-total-length",
              "ipv4-id",
              "ipv4-frag",
              "ip-ttl-hop-limit",
              "ip-protocol-next-header",
              "ipv4-checksum",
              "ipv6-flow-label",
              "ipv6-payload-length",
              "src-port",
              "dst-port",
              "seqno",
              "ackno",
              "tcp-doff-reserved-ns",
              "tcp-flags",
              "tcp-window",
              "tcp-checksum",
              "tcp-urgent",
              "cqe",
              "cqe-pkt-info",
              "cqe-lro-tcppsh-abort-dupack",
              "cqe-min-ttl",
              "cqe-tcp-window",
              "cqe-ack-seq",
              "cqe-rx-hash",
              "cqe-rx-hash-type",
              "cqe-csum",
              "cqe-hds-ip-ext",
              "cqe-l4-hdr-type-etc",
              "cqe-vlan-info",
              "cqe-byte-count",
              "cqe-timestamp",
              "cqe-flow-table-metadata",
              "cqe-sop-rxdrop-qpn-flowtag",
              "cqe-wqe-counter",
              "cqe-op-own",
              "lro-enable-mask",
              "lro-min-mss",
              "lro-psh-cap",
              "lro-timestamp-cap",
              "lro-max-size",
              "lro-max-size-mode",
              "lro-timeout-us",
              "LRO_PSH",
              "lro-timestamp-valid",
              "tcp-timestamp-present",
              "tcp-tsval",
              "tcp-tsecr",
              "lro-tsval",
              "lro-tsecr",
              "timestamp-change",
              "lro-ackno",
              "ack-change",
              "lro-window",
              "window-change",
              "lro-min-ttl",
              "ttl-change",
              "tcp-option-profile",
              "ip-ecn",
              "tcp-ece",
              "tcp-cwr",
              "sequence-relation",
              "mean-segment-payload",
              "lro-dup-ack-count"});
}
inline void csv_record(std::ostream &out, const record &r, const observation &o, const batch &b,
                       uint64_t batch_id)
{
    const auto &s = o.sizes;
    const auto &c = b.context;
    auto num = [](uint64_t value, bool valid = true) -> std::string {
        return valid ? std::to_string(value) : "-";
    };
    bool v4 = o.ip_valid && s.ip_version == 4, v6 = o.ip_valid && s.ip_version == 6;
    bool tcp = r.tcp_len >= 20;
    bool layout_ok = o.tcp_valid;
    auto cq = [&](uint64_t value) { return num(value, r.cqe_valid); };
    const bool lro = r.cqe_valid && s.lro_segments;
    const bool timestamp = o.tcp_valid && o.options_valid && o.timestamp;
    const bool lro_timestamp = lro && o.lro_timestamp_valid == 1;
    std::ostringstream mean_payload;
    if (lro && layout_ok) {
        mean_payload << double(s.payload_bytes) / s.lro_segments;
    } else {
        mean_payload << '-';
    }
    csv_line(
        out,
        {num(batch_id),
         num(b.ring_id),
         num(b.generation),
         num(b.if_index),
         num(o.flow_id, o.flow_id != 0),
         o.tuple.empty() ? "-" : o.tuple,
         num(o.expected, o.expected_valid),
         num(r.sw_time_ns, r.sw_time_ns != 0),
         o.incomplete ? "true" : "false",
         o.excluded.empty() ? "-" : o.excluded,
         r.striding ? "STRQ" : "RQ",
         num(r.frame_bytes),
         num(r.frame_mod64),
         num(s.l2_bytes, r.eth_len >= 14),
         num(s.l3_bytes, o.ip_valid),
         num(s.tcp_bytes, tcp),
         num(s.payload_bytes, layout_ok),
         num(s.payload_offset, layout_ok),
         num(s.payload_mod64, layout_ok),
         num(s.payload_bytes % 64, layout_ok),
         num(s.lro_segments, r.cqe_valid),
         abort_name(r),
         o.disq,
         r.eth_len ? hex_bytes(r.ethernet, std::min<size_t>(r.eth_len, sizeof(r.ethernet))) : "-",
         r.ip_len ? hex_bytes(r.ip, std::min<size_t>(r.ip_len, sizeof(r.ip))) : "-",
         r.ext_count ? hex_bytes(r.extensions, std::min<size_t>(r.ext_count, sizeof(r.extensions)))
                     : "-",
         r.tcp_len ? hex_bytes(r.tcp, std::min<size_t>(r.tcp_len, sizeof(r.tcp))) : "-",
         r.tcp_len > 20 ? hex_bytes(r.tcp + 20, std::min<size_t>(r.tcp_len, sizeof(r.tcp)) - 20)
                        : "-",
         num(s.ip_version, o.ip_valid),
         num(v4 ? r.ip[1] : ((r.ip[0] & 15U) << 4) | (r.ip[1] >> 4), o.ip_valid),
         num(u16(r.ip + 2), v4),
         num(u16(r.ip + 4), v4),
         num(u16(r.ip + 6), v4),
         num(r.ip[v4 ? 8 : 7], o.ip_valid),
         num(r.ip[v4 ? 9 : 6], o.ip_valid),
         num(u16(r.ip + 10), v4),
         num(u32(r.ip) & 0xfffff, v6),
         num(u16(r.ip + 4), v6),
         num(u16(r.tcp), tcp),
         num(u16(r.tcp + 2), tcp),
         num(u32(r.tcp + 4), tcp),
         num(u32(r.tcp + 8), tcp),
         num(r.tcp[12], tcp),
         num(r.tcp[13], tcp),
         num(u16(r.tcp + 14), tcp),
         num(u16(r.tcp + 16), tcp),
         num(u16(r.tcp + 18), tcp),
         r.cqe_valid ? hex_bytes(r.cqe, sizeof(r.cqe)) : "-",
         cq(r.cqe[0]),
         cq(r.cqe[4]),
         cq(r.cqe[5]),
         cq(u16(r.cqe + 6)),
         cq(u32(r.cqe + 8)),
         cq(u32(r.cqe + 12)),
         cq(r.cqe[16]),
         cq(u16(r.cqe + 20)),
         cq(r.cqe[28]),
         cq(r.cqe[29]),
         cq(u16(r.cqe + 30)),
         cq(u32(r.cqe + 44)),
         cq(u64(r.cqe + 48)),
         cq(u32(r.cqe + 36)),
         cq(u32(r.cqe + 56)),
         cq(u16(r.cqe + 60)),
         cq(r.cqe[63]),
         num(c.enable_mask, c.tir_known),
         num(c.min_mss, c.caps_known),
         num(c.psh, c.caps_known),
         num(c.timestamp, c.caps_known),
         num(c.max_lro_bytes, c.tir_known),
         num(c.max_size_mode, c.caps_known),
         num(c.timeout_us, c.tir_known),
         num(o.lro_psh, lro),
         num(o.lro_timestamp_valid, lro),
         num(o.timestamp, o.tcp_valid && o.options_valid),
         num(o.tsval, timestamp),
         num(o.tsecr, timestamp && (r.tcp[13] & 0x10)),
         num(u32(r.cqe + 48), lro_timestamp),
         num(u32(r.cqe + 52), lro_timestamp && o.lro_ack_valid),
         o.timestamp_change,
         num(u32(r.cqe + 8), o.lro_ack_valid),
         o.ack_change,
         num(u16(r.cqe + 6), lro),
         o.window_change,
         num(r.cqe[5], lro),
         lro && o.ip_valid ? (r.ip[v4 ? 8 : 7] == r.cqe[5] ? "same" : "changed") : "-",
         o.option_profile,
         num(o.ecn, o.ip_valid),
         num((r.tcp[13] >> 6) & 1, tcp),
         num((r.tcp[13] >> 7) & 1, tcp),
         sequence_relation(o),
         mean_payload.str(),
         num(r.cqe[4] & 15, lro)});
}
} // namespace xlio_rx_layout
#endif
