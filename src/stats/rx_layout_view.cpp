/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "core/util/xlio_stats.h"
#include "rx_layout_summary.h"
#include "rx_analysis_csv.h"
#include <fstream>
#include "rx_layout_view.h"
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <signal.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace {
volatile sig_atomic_t capture_stopped = 0;
void stop_capture(int)
{
    capture_stopped = 1;
}
struct mapping {
    int fd = -1;
    void *address = MAP_FAILED;
    size_t size = 0;
    ~mapping()
    {
        if (address != MAP_FAILED && munmap(address, size) != 0) {
            fprintf(stderr, "xliostat: cannot unmap statistics: %s\n", strerror(errno));
        }
        if (fd >= 0) {
            close(fd);
        }
    }
};
struct signals {
    struct sigaction old_int {
    }, old_term {};
    signals()
    {
        capture_stopped = 0;
        struct sigaction action {};
        action.sa_handler = stop_capture;
        sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, &old_int);
        sigaction(SIGTERM, &action, &old_term);
    }
    ~signals()
    {
        sigaction(SIGINT, &old_int, nullptr);
        sigaction(SIGTERM, &old_term, nullptr);
    }
};

void print_batch(unsigned index, const xlio_rx_layout::batch &b, xlio_rx_layout::analyzer &analysis,
                 uint64_t batch_id, std::ostream *csv)
{
    using namespace xlio_rx_layout;
    std::vector<observation> observations;
    for (unsigned i = 0; i < b.count; ++i) {
        observations.push_back(analysis.inspect(b.records[i], b, batch_id));
        if (csv) {
            csv_record(*csv, b.records[i], observations.back(), b, batch_id);
        }
    }
    auto s = summarize(observations);
    printf("Ring %u id=0x%" PRIx64 " ifindex=%u generation=%" PRIu64 ": %u/%u samples%s\n", index,
           b.ring_id, b.if_index, b.generation, b.count, b.requested, b.closed ? " (closed)" : "");
    if (!b.count) {
        printf("  No traffic\n");
        return;
    }
    const auto &c = b.context;
    auto n = [](unsigned value, bool valid) -> std::string {
        return valid ? std::to_string(value) : "-";
    };
    printf("  LRO context: enable-mask=%s min-mss=%s psh=%s timestamp=%s max-size=%s size-mode=%s "
           "timeout-us=%s\n",
           n(c.enable_mask, c.tir_known).c_str(), n(c.min_mss, c.caps_known).c_str(),
           n(c.psh, c.caps_known).c_str(), n(c.timestamp, c.caps_known).c_str(),
           n(c.max_lro_bytes, c.tir_known).c_str(), n(c.max_size_mode, c.caps_known).c_str(),
           n(c.timeout_us, c.tir_known).c_str());
    for (auto *rows : {&s.rows, &s.excluded}) {
        if (rows->empty()) {
            continue;
        }
        if (rows == &s.excluded) {
            printf(" Excluded packets (included in sample count and CSV):\n");
        }
        printf(" Count   Share RQ   IP LRO Hdr L2/IP/TCP   Frame Payload Offset A%%64 L%%64 "
               "Flags Incomplete LRO_PSH TS_valid TS_change ACK_change Win_change "
               "lro_abrt    lro disq%s\n",
               rows == &s.excluded ? " | excluded" : "");
        for (const auto &row : *rows) {
            const auto &o = row.item;
            const auto &r = o.sizes;
            std::string abrt = r.lro_segments ? abort_reason_name(o.abrt) : "-";
            char flags[8];
            snprintf(flags, sizeof(flags), "0x%02x", r.tcp_flags);
            printf(
                " %5u %6.2f%% %-4s %2s %3s %3s %2s/%2s/%2s %8u %7s %6s %4s %4s %5s %10s "
                "%7s %8s %-10s %-11s %-10s %-11s %s%s%s\n",
                row.count, 100.0 * row.count / b.count, r.striding ? "STRQ" : "RQ",
                n(r.ip_version, o.ip_valid).c_str(), n(r.lro_segments, o.cqe_valid).c_str(),
                n(r.l2_bytes + r.l3_bytes + r.tcp_bytes, o.tcp_valid).c_str(),
                n(r.l2_bytes, o.ethernet_valid).c_str(), n(r.l3_bytes, o.ip_valid).c_str(),
                n(r.tcp_bytes, o.tcp_fields_valid).c_str(), r.frame_bytes,
                n(r.payload_bytes, o.tcp_valid).c_str(), n(r.payload_offset, o.tcp_valid).c_str(),
                n(r.payload_mod64, o.tcp_valid).c_str(),
                n(r.payload_bytes % 64, o.tcp_valid).c_str(), o.tcp_fields_valid ? flags : "-",
                o.incomplete ? "true" : "false", n(o.lro_psh, o.lro_psh >= 0).c_str(),
                n(o.lro_timestamp_valid, o.lro_timestamp_valid >= 0).c_str(),
                o.timestamp_change.c_str(), o.ack_change.c_str(), o.window_change.c_str(),
                abrt.c_str(), o.disq.c_str(), o.excluded.empty() ? "" : " | ", o.excluded.c_str());
        }
    }
    printf(" Data=%u, control-only=%u", s.data, s.control);
    if (s.data) {
        printf("; data alignment: offset=64 %.2f%%, address%%64=0 %.2f%%, length%%64=0 %.2f%%",
               100.0 * s.offset64 / s.data, 100.0 * s.address64 / s.data,
               100.0 * s.length64 / s.data);
    }
    printf("\n");
}
} // namespace

int print_rx_analysis(int pid, const std::string &directory, unsigned samples, int interval,
                      int cycles, const std::string &csv_path)
{
    using namespace xlio_rx_layout;
    if (interval < 1 || samples < 1 || samples > capacity || cycles < 0) {
        fprintf(stderr, "xliostat: RX analysis needs interval >= 1 and samples in [1, %u]\n",
                capacity);
        return 1;
    }
    const std::string path = directory + "/xliostat." + std::to_string(pid);
    mapping m;
    m.fd = open(path.c_str(), O_RDWR | O_CLOEXEC);
    if (m.fd < 0) {
        fprintf(stderr, "xliostat: RX capture needs read/write access to %s: %s\n", path.c_str(),
                strerror(errno));
        return 1;
    }
    if (flock(m.fd, LOCK_EX | LOCK_NB) != 0) {
        fprintf(stderr, "xliostat: RX capture is busy or cannot be locked: %s\n", strerror(errno));
        return 1;
    }
    struct stat info {};
    if (fstat(m.fd, &info) || info.st_size < static_cast<off_t>(sizeof(sh_mem_t))) {
        fprintf(stderr, "xliostat: incomplete statistics header\n");
        return 1;
    }
    m.size = sizeof(sh_mem_t);
    m.address = mmap(nullptr, m.size, PROT_READ, MAP_SHARED, m.fd, 0);
    if (m.address == MAP_FAILED) {
        fprintf(stderr, "xliostat: cannot map statistics header: %s\n", strerror(errno));
        return 1;
    }
    auto *header = static_cast<const sh_mem_t *>(m.address);
    if (memcmp(header->stats_protocol_ver, STATS_PROTOCOL_VER,
               std::min(sizeof(header->stats_protocol_ver), sizeof(STATS_PROTOCOL_VER))) != 0) {
        fprintf(stderr, "xliostat: incompatible statistics protocol\n");
        return 1;
    }
    size_t sockets = header->max_skt_inst_num;
    const size_t limit =
        (std::numeric_limits<size_t>::max() - sizeof(sh_mem_t) - sizeof(region) - 63U) /
        sizeof(socket_instance_block_t);
    if (sockets > limit) {
        fprintf(stderr, "xliostat: invalid statistics size\n");
        return 1;
    }
    size_t offset = extension_offset(SHMEM_STATS_SIZE(sockets));
    size_t full_size = offset + sizeof(region);
    if (static_cast<uint64_t>(info.st_size) < full_size) {
        fprintf(stderr, "xliostat: RX analysis capture is not supported by this library\n");
        return 1;
    }
    if (munmap(m.address, m.size) != 0) {
        fprintf(stderr, "xliostat: cannot unmap statistics header: %s\n", strerror(errno));
        return 1;
    }
    m.size = full_size;
    m.address = mmap(nullptr, m.size, PROT_READ | PROT_WRITE, MAP_SHARED, m.fd, 0);
    if (m.address == MAP_FAILED) {
        fprintf(stderr, "xliostat: cannot map RX capture: %s\n", strerror(errno));
        return 1;
    }
    auto *capture = reinterpret_cast<region *>(static_cast<char *>(m.address) + offset);
    if (!valid_region(*capture)) {
        fprintf(stderr, "xliostat: unsupported RX capture version or record layout\n");
        return 1;
    }
    mapping csv_target;
    std::ofstream csv;
    if (!csv_path.empty()) {
        // Open without truncation first. Comparing the open inode also handles
        // hard links/symlinks. Reopen this descriptor via procfs, never the
        // user-supplied path, so a rename cannot race the alias check.
        csv_target.fd = open(csv_path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0666);
        struct stat destination {};
        if (csv_target.fd < 0 || fstat(csv_target.fd, &destination) ||
            (destination.st_dev == info.st_dev && destination.st_ino == info.st_ino)) {
            fprintf(stderr,
                    "xliostat: CSV must be writable and distinct from the live statistics file\n");
            return 1;
        }
        csv.open("/proc/self/fd/" + std::to_string(csv_target.fd));
        if (!csv) {
            fprintf(stderr, "xliostat: cannot open CSV %s\n", csv_path.c_str());
            return 1;
        }
        csv_header(csv);
    }
    analyzer analysis;
    auto sample_batch = std::make_unique<batch>();
    signals signal_guard;
    for (auto &s : capture->slots) {
        arm(s, s.control.load(std::memory_order_acquire), samples);
    }
    printf("xliostat: RX analysis samples for pid %d; up to %u records/ring every "
           "%ds\n",
           pid, samples, interval);
    printf(
        "Sizes describe RX completions; LRO aggregates do not reveal every "
        "wire segment. Disqualifiers are inferred from observed packets, not HW session state.\n");
    fflush(stdout);
    for (int cycle = 0; !capture_stopped && (!cycles || cycle < cycles); ++cycle) {
        struct timespec delay {
            interval, 0
        };
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR && !capture_stopped) {
        }
        if (capture_stopped) {
            break;
        }
        printf("\nBatch %d\n", cycle + 1);
        bool shown = false;
        for (unsigned i = 0; i < max_rings; ++i) {
            auto &s = capture->slots[i];
            auto &b = *sample_batch;
            if (reader_copy(s, b)) {
                print_batch(i, b, analysis, cycle + 1, csv.is_open() ? &csv : nullptr);
                shown = true;
            } else {
                auto token = s.control.load(std::memory_order_acquire);
                if (state(token) == phase::idle && arm(s, token, samples)) {
                    token = s.control.load(std::memory_order_acquire);
                }
                if (state(token) == phase::recording) {
                    // Slot identity stays pinned until this request has been consumed.
                    auto n = captured(token);
                    printf("Ring %u ifindex=%u: %s\n", i, s.if_index,
                           progress_text(n, target(token)).c_str());
                    shown = true;
                }
            }
            if (!cycles || cycle + 1 < cycles) {
                arm(s, s.control.load(std::memory_order_acquire), samples);
            }
        }
        if (!shown) {
            printf("No traffic (no active capture rings)\n");
        }
        auto failures = capture->registration_failures.load(std::memory_order_relaxed);
        if (failures) {
            printf("Capture coverage limited: %u ring registrations had no free "
                   "capture slot\n",
                   failures);
        }
        if (csv.is_open()) {
            csv.flush();
            if (!csv) {
                fprintf(stderr, "xliostat: CSV write failed\n");
                return 1;
            }
        }
        fflush(stdout);
        if (kill(pid, 0) != 0 && errno == ESRCH) {
            printf("xliostat: target process exited\n");
            break;
        }
    }
    return 0;
}

const char *rx_analysis_help()
{
    return R"help(
RX analysis (--rx-analysis, optionally -C/--csv_file PATH):
  --rx-samples N: up to N packet completions per ring per batch (1..256).
  Excluded packets count toward N. An LRO aggregate is one completion.
  Capture runs only on request; closing a ring publishes its partial batch.
  No traffic / Collecting samples: empty / partial batch.
  Sizes are bytes. Missing or inapplicable values are '-'.
  Histograms group identical layouts, reasons and categories, not exact ACKs
  or timestamp values. Headers are captured before XLIO repairs LRO headers.

  Histogram:
    Count: number of records with this layout and these categories.
    Share: percentage of all records in this ring batch.
    RQ: STRQ (striding) or RQ (regular).
    IP: IP version.
    LRO: CQE segment count; 0=no session, 1=single packet, >1=aggregate.
    Hdr: L2 + IP + TCP header bytes.
    L2/IP/TCP: individual header lengths, including tags/options/extensions.
    Frame: completed Ethernet frame size.
    Payload: aggregate TCP payload size for LRO>1.
    Offset: payload offset from Ethernet frame start.
    A%64: payload address modulo 64.
    L%64: payload length modulo 64.
    Flags: first packet's raw TCP flags, before LRO repair.
    Incomplete: some requested headers or metadata were not recorded.
    LRO_PSH: CQE PSH across the session; valid only for LRO>0.
    TS_valid: CQE contains LRO TCP timestamps; valid only for LRO>0.
    TS_change: none, first-only, final-only, same, changed or malformed.
      Compares first/final TSval and, when both ACKs are valid, TSecr.
      Applies only to LRO>0; first/final refer to packet header / CQE.
    ACK_change: same, advanced, regressed, ambiguous or first-unset.
      Uses modulo-2^32 ACK comparison; a half-space difference is ambiguous.
      Requires LRO>0 and CQE L4 type 3 or 4; first-unset means no first ACK.
    Win_change: zero (final window=0), same, increased or decreased.
      Compares first/final raw windows for LRO>0; no window scaling applied.
    lro_abrt: HW reason: 0:max-size, 1:timeout, 2:exception, 3:Other.
      Valid for LRO>0. The triggering packet is generally outside the aggregate.
    lro disq: observed disqualifiers for LRO=0; '-' for LRO>0.
      Inferred from samples/settings, not proof of the NIC's decision.
      'not validated' does not prove bad checksum. NOP/EOL padding is allowed.
      Resource exhaustion and unsampled packets cannot be diagnosed.
    Excluded: no safely interpretable complete TCP layout; separate histogram.
    Data: packets with TCP payload; alignment percentages use these packets.
    control-only: TCP packets without payload.

  CSV: one row per completion, including excluded records, in ring capture order.
  There is no global packet ordering across rings. Raw CQE fields require
  opcode/validity checks; a zero union value does not make every use applicable.
  IPv4 option and IPv6 extension bodies are omitted; extension types are kept.
  Application payload is never captured. LRO timestamps are TCP option values,
  not NIC clock values or a measurement of aggregation duration.
    batch: Display update number.
    ring-id: Process-wide monotonic ring registration ID.
    ring-generation: Capture-slot generation; disambiguates slot reuse.
    ifindex: Interface index.
    flow-id: Directional-flow ID retained across batches; bounded to 4096 active IDs.
    tuple: Interface, source/destination IP:port and VLAN context; eviction gives a new ID.
    expected-seqno: Previous observed sequence + aggregate payload + SYN + FIN, modulo 2^32.
      Unavailable at batch/ring changes, SYN or after lost/malformed context.
      No inference spans sampling gaps; FIN/RST ends continuity.
    sw-time-ns: CLOCK_MONOTONIC_RAW at SW completion processing; includes polling delay.
      Not wire-arrival time.
    incomplete: Some requested headers/metadata unavailable; omitted payload does not set it.
    excluded: Reason no complete TCP layout could be interpreted, or '-'.
    rq: STRQ (striding) or RQ (regular).
    frame-bytes: Completed Ethernet frame size.
    frame-address-mod64: Ethernet frame address modulo 64.
    l2-bytes: Ethernet header length, including captured VLAN tags.
    ip-bytes: IP header length, including options/extensions.
    tcp-bytes: TCP header length, including options.
    payload-bytes: TCP payload size; aggregate completion payload for LRO>1.
    payload-offset: Payload offset from Ethernet frame start.
    payload-address-mod64: Payload address modulo 64.
    payload-length-mod64: Payload length modulo 64.
    LRO: CQE segment count: 0=no session, 1=single packet, >1=aggregate.
    lro_abrt: HW completion reason; valid for LRO>0. See histogram description.
    lro disq: Observed disqualifiers for LRO=0; inferred, not HW session state.
    ethernet-header: Bounded raw Ethernet header in hex, before repair.
    ip-header: Raw IP base header in hex; option/extension bodies are omitted.
    ipv6-extension-types: Bounded IPv6 extension-type list in hex.
    tcp-header: Raw TCP header in hex, including up to 40 option bytes.
    tcp-options: Raw TCP option bytes in hex.
    ip-version: 4 or 6.
    ip-dscp-ecn: Combined IP DSCP+ECN byte.
    ipv4-total-length: First packet's raw IPv4 total length.
    ipv4-id: First packet's raw IPv4 identification.
    ipv4-frag: Raw IPv4 flags and fragment offset.
    ip-ttl-hop-limit: First packet's TTL (IPv4) or hop limit (IPv6).
    ip-protocol-next-header: Raw base-IP protocol / next-header byte.
    ipv4-checksum: Raw IPv4 header checksum.
    ipv6-flow-label: Raw IPv6 flow label.
    ipv6-payload-length: First packet's raw IPv6 payload length.
    src-port: Raw TCP source port.
    dst-port: Raw TCP destination port.
    seqno: First packet's raw TCP sequence number.
    ackno: First packet's raw TCP ACK number; meaningful only when ACK is set.
    tcp-doff-reserved-ns: Raw TCP byte containing data offset, reserved bits and NS.
    tcp-flags: First packet's raw TCP flags.
    tcp-window: First packet's raw advertised window; no scaling applied.
    tcp-checksum: Raw TCP checksum.
    tcp-urgent: Raw TCP urgent pointer.
    cqe: Full raw 64-byte CQE in hex.
    cqe-pkt-info: Raw CQE packet-info byte.
    cqe-lro-tcppsh-abort-dupack: Raw packed LRO timestamp-valid/PSH/abort/dupack byte.
    cqe-min-ttl: Raw CQE minimum TTL / hop limit.
    cqe-tcp-window: Raw CQE final LRO window union field.
    cqe-ack-seq: Raw CQE final LRO ACK union field.
    cqe-rx-hash: Raw RX hash.
    cqe-rx-hash-type: Raw RX hash type.
    cqe-csum: Raw HW checksum; coverage depends on completion type.
    cqe-hds-ip-ext: Raw validation bits.
    cqe-l4-hdr-type-etc: Raw L3/L4 types, fragment/extension and VLAN flags.
    cqe-vlan-info: Raw VLAN TCI.
    cqe-byte-count: Raw byte-count field, including STRQ encoding.
    cqe-timestamp: Raw 64-bit union: LRO TCP timestamps when valid, otherwise CQ clock.
    cqe-flow-table-metadata: Raw flow-table metadata.
    cqe-sop-rxdrop-qpn-flowtag: Raw packed SOP/drop/QPN/flow-tag metadata.
    cqe-wqe-counter: Raw WQE counter.
    cqe-op-own: Raw opcode, format and ownership byte.
    lro-enable-mask: Effective TIR IP-family mask: IPv4=1, IPv6=2.
    lro-min-mss: Device minimum TCP payload for LRO.
    lro-psh-cap: Device PSH support boolean.
    lro-timestamp-cap: Device TCP timestamp support boolean.
    lro-max-size: Configured LRO size limit.
    lro-max-size-mode: 0=TCP header+data; 1=whole frame.
    lro-timeout-us: Configured TIR LRO timeout in microseconds.
    LRO_PSH: Decoded aggregate PSH bit, valid only for LRO>0.
    lro-timestamp-valid: Decoded LRO timestamp-valid bit, valid only for LRO>0.
    tcp-timestamp-present: First packet has a well-formed timestamp option.
    tcp-tsval: First packet's TCP TSval; unavailable for malformed options.
    tcp-tsecr: First packet's TCP TSecr; requires timestamp option and ACK flag.
    lro-tsval: Final CQE TCP TSval; requires LRO timestamp-valid.
    lro-tsecr: CQE TCP TSecr; requires LRO timestamp-valid and L4 type 3 or 4.
    timestamp-change: First/final TCP timestamp category; see TS_change.
    lro-ackno: Decoded final ACK; requires LRO>0 and CQE L4 type 3 or 4.
    ack-change: First/final ACK category; see ACK_change.
    lro-window: Decoded final raw window; valid for LRO>0.
    window-change: First/final raw window category; see Win_change.
    lro-min-ttl: Decoded session minimum TTL / hop limit; valid for LRO>0.
    ttl-change: First TTL/hop limit versus session minimum: same or changed.
    tcp-option-profile: none, timestamp-only, SACK, other, malformed or unknown.
    ip-ecn: IP ECN bits: 0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE.
    tcp-ece: First packet's TCP ECE bit.
    tcp-cwr: First packet's TCP CWR bit.
    sequence-relation: unknown, contiguous, forward-gap or overlap within a capture batch.
      Describes observations, not proof of loss/retransmission; half-space is unknown.
    mean-segment-payload: Aggregate payload divided by LRO count; may be fractional.
      Valid for LRO>0; not an original segment-size distribution.
    lro-dup-ack-count: Decoded diagnostic duplicate-ACK count; valid for LRO>0.
      Expected to be zero according to the PRM; not a reliable loss counter.
)help";
}
