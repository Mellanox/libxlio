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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cinttypes>
#include "core/util/utils.h"
#include "core/util/xlio_stats.h"
#include "core/lwip/tcp.h"
#include "core/xlio_extra.h"
#include "core/util/sys_vars.h"

typedef enum { e_K = 1024, e_M = 1048576 } units_t;

user_params_t user_params;

#define BYTES_TRAFFIC_UNIT e_K

const char *to_str_socket_type(int type)
{
    switch (type) {
    case SOCK_STREAM:
        return "TCP";
    case SOCK_DGRAM:
        return "UDP";
    case SOCK_RAW:
        return "RAW";
    default:
        break;
    }
    return "???";
}

const char *to_str_socket_type_netstat_like(int type, sa_family_t family)
{
    switch (type) {
    case SOCK_STREAM:
        return (family == AF_INET6) ? "tcp6" : "tcp";
    case SOCK_DGRAM:
        return (family == AF_INET6) ? "udp6" : "udp";
    case SOCK_RAW:
        return "raw";
    default:
        break;
    }
    return "???";
}

// Print statistics for offloaded sockets
void print_full_stats(socket_stats_t *p_si_stats, mc_grp_info_t *p_mc_grp_info, FILE *filename)
{

    if (!filename) {
        return;
    }

    bool b_any_activiy = false;
    char post_fix[3] = "";

    if (user_params.print_details_mode == e_deltas) {
        strcpy(post_fix, "/s");
    }
    fprintf(filename, "======================================================\n");
    fprintf(filename, "\tFd=[%d]\n", p_si_stats->fd);

    //
    // Socket information
    //
    fprintf(filename, "- %s", to_str_socket_type(p_si_stats->socket_type));
    fprintf(filename, ", %s", p_si_stats->b_blocking ? "Blocked" : "Non-blocked");

    //
    // Multicast information
    //
    if (p_si_stats->socket_type == SOCK_DGRAM) {
        fprintf(filename, ", MC Loop %s", p_si_stats->b_mc_loop ? "Enabled " : "Disabled");
        if (!p_si_stats->mc_tx_if.is_anyaddr()) {
            fprintf(filename, ", MC IF = [%s]",
                    p_si_stats->mc_tx_if.to_str(p_si_stats->sa_family).c_str());
        }
    }
    fprintf(filename, "\n");

    //
    // Bounded + Connected information
    //
    if (!p_si_stats->bound_if.is_anyaddr() || p_si_stats->bound_port) {
        fprintf(filename, "- Local Address   = [%s:%d]\n",
                p_si_stats->bound_if.to_str(p_si_stats->sa_family).c_str(),
                ntohs(p_si_stats->bound_port));
    }
    if (!p_si_stats->connected_ip.is_anyaddr() || p_si_stats->connected_port) {
        fprintf(filename, "- Foreign Address = [%s:%d]\n",
                p_si_stats->connected_ip.to_str(p_si_stats->sa_family).c_str(),
                ntohs(p_si_stats->connected_port));
    }
    if (p_mc_grp_info) {
        for (int grp_idx = 0; grp_idx < p_mc_grp_info->max_grp_num; grp_idx++) {
            if (p_si_stats->mc_grp_map.test(grp_idx)) {
                fprintf(filename, "- Member of = [%s]\n",
                        p_mc_grp_info->mc_grp_tbl[grp_idx].mc_grp.to_str().c_str());
            }
        }
    }
    if ((p_si_stats->threadid_last_rx != 0) || (p_si_stats->threadid_last_tx != 0)) {
        fprintf(filename, "- Thread Id Rx: %5u, Tx: %5u\n", p_si_stats->threadid_last_rx,
                p_si_stats->threadid_last_tx);
    }

    //
    // Ring Allocation Logic information
    //
    //
    if (p_si_stats->ring_alloc_logic_rx == RING_LOGIC_PER_USER_ID) {
        fprintf(filename, "- RX: Ring User ID = %lu\n", p_si_stats->ring_user_id_rx);
    }
    if (p_si_stats->ring_alloc_logic_tx == RING_LOGIC_PER_USER_ID) {
        fprintf(filename, "- TX: Ring User ID = %lu\n", p_si_stats->ring_user_id_tx);
    }

    //
    // Socket statistics
    //
    if (p_si_stats->counters.n_tx_sent_byte_count || p_si_stats->counters.n_tx_sent_pkt_count ||
        p_si_stats->counters.n_tx_eagain || p_si_stats->counters.n_tx_errors) {
        fprintf(filename,
                "Tx Offload: %" PRIu64 " / %u / %u / %u [kilobytes/packets/eagains/errors]%s\n",
                p_si_stats->counters.n_tx_sent_byte_count / BYTES_TRAFFIC_UNIT,
                p_si_stats->counters.n_tx_sent_pkt_count, p_si_stats->counters.n_tx_eagain,
                p_si_stats->counters.n_tx_errors, post_fix);
        b_any_activiy = true;
    }
    if (p_si_stats->counters.n_tx_os_bytes || p_si_stats->counters.n_tx_os_packets ||
        p_si_stats->counters.n_tx_os_eagain || p_si_stats->counters.n_tx_os_errors) {
        fprintf(filename,
                "Tx OS info: %" PRIu64 " / %u / %u / %u [kilobytes/packets/eagains/errors]%s\n",
                p_si_stats->counters.n_tx_os_bytes / BYTES_TRAFFIC_UNIT,
                p_si_stats->counters.n_tx_os_packets, p_si_stats->counters.n_tx_os_eagain,
                p_si_stats->counters.n_tx_os_errors, post_fix);
        b_any_activiy = true;
    }
    if (p_si_stats->counters.n_tx_dummy) {
        fprintf(filename, "Tx Dummy messages : %d\n", p_si_stats->counters.n_tx_dummy);
        b_any_activiy = true;
    }
    if (p_si_stats->counters.n_rx_bytes || p_si_stats->counters.n_rx_packets ||
        p_si_stats->counters.n_rx_eagain || p_si_stats->counters.n_rx_errors) {
        fprintf(filename,
                "Rx Offload: %" PRIu64 " / %u / %u / %u [bytes/packets/eagains/errors]%s\n",
                p_si_stats->counters.n_rx_bytes, p_si_stats->counters.n_rx_packets,
                p_si_stats->counters.n_rx_eagain, p_si_stats->counters.n_rx_errors, post_fix);
        b_any_activiy = true;
        fprintf(filename,
                "Rx data packets: %" PRIu64 " / %u / %u / %u [bytes/packets/frags/chained]\n",
                p_si_stats->counters.n_rx_bytes, p_si_stats->counters.n_rx_data_pkts,
                p_si_stats->counters.n_rx_frags, p_si_stats->counters.n_gro);
        if (p_si_stats->counters.n_rx_data_pkts) {
            fprintf(filename, "Avg. aggr packet size: %" PRIu64 " fragments per packet: %.1f\n",
                    p_si_stats->counters.n_rx_bytes / p_si_stats->counters.n_rx_data_pkts,
                    static_cast<double>(p_si_stats->counters.n_rx_frags) /
                        p_si_stats->counters.n_rx_data_pkts);
        }
    }
    if (p_si_stats->counters.n_rx_os_bytes || p_si_stats->counters.n_rx_os_packets ||
        p_si_stats->counters.n_rx_os_eagain || p_si_stats->counters.n_rx_os_errors) {
        fprintf(filename,
                "Rx OS info: %" PRIu64 " / %u / %u / %u [kilobytes/packets/eagains/errors]%s\n",
                p_si_stats->counters.n_rx_os_bytes / BYTES_TRAFFIC_UNIT,
                p_si_stats->counters.n_rx_os_packets, p_si_stats->counters.n_rx_os_eagain,
                p_si_stats->counters.n_rx_os_errors, post_fix);
        b_any_activiy = true;
    }
    if (p_si_stats->counters.n_rx_data_pkts || p_si_stats->n_rx_ready_pkt_count) {
        fprintf(filename, "Rx byte: cur %lu / max %u / dropped%s %u\n",
                p_si_stats->n_rx_ready_byte_count, p_si_stats->counters.n_rx_ready_byte_max,
                post_fix, p_si_stats->counters.n_rx_ready_byte_drop);
        fprintf(filename, "Rx pkt : cur %u / max %u / dropped%s %u\n",
                p_si_stats->n_rx_ready_pkt_count, p_si_stats->counters.n_rx_ready_pkt_max, post_fix,
                p_si_stats->counters.n_rx_ready_pkt_drop);
        b_any_activiy = true;
    }
    if (p_si_stats->strq_counters.n_strq_total_strides) {
        fprintf(filename, "Rx RQ Strides: %" PRIu64 " / %u [total/max-per-packet]%s\n",
                p_si_stats->strq_counters.n_strq_total_strides,
                p_si_stats->strq_counters.n_strq_max_strides_per_packet, post_fix);
        b_any_activiy = true;
    }
    if (p_si_stats->counters.n_rx_poll_miss || p_si_stats->counters.n_rx_poll_hit) {
        double rx_poll_hit = (double)p_si_stats->counters.n_rx_poll_hit;
        double rx_poll_hit_percentage =
            (rx_poll_hit / (rx_poll_hit + (double)p_si_stats->counters.n_rx_poll_miss)) * 100;
        fprintf(filename, "Rx poll: %u / %u (%2.2f%%) [miss/hit]\n",
                p_si_stats->counters.n_rx_poll_miss, p_si_stats->counters.n_rx_poll_hit,
                rx_poll_hit_percentage);
        b_any_activiy = true;
    }

    if (p_si_stats->counters.n_rx_migrations || p_si_stats->counters.n_tx_migrations) {
        fprintf(filename, "Ring migrations Rx: %u, Tx: %u\n", p_si_stats->counters.n_rx_migrations,
                p_si_stats->counters.n_tx_migrations);
    }

    if (p_si_stats->counters.n_tx_retransmits) {
        fprintf(filename, "Retransmissions: %u\n", p_si_stats->counters.n_tx_retransmits);
    }

    if (p_si_stats->counters.n_tx_sendfile_fallbacks) {
        fprintf(filename, "Sendfile: fallbacks %u / overflows %u\n",
                p_si_stats->counters.n_tx_sendfile_fallbacks,
                p_si_stats->counters.n_tx_sendfile_overflows);
    }

#ifdef DEFINED_UTLS
    if (p_si_stats->tls_tx_offload || p_si_stats->tls_rx_offload) {
        fprintf(filename, "TLS Offload: version %04x / cipher %u / TX %s / RX %s\n",
                p_si_stats->tls_version, p_si_stats->tls_cipher,
                p_si_stats->tls_tx_offload ? "On" : "Off",
                p_si_stats->tls_rx_offload ? "On" : "Off");
    }
    if (p_si_stats->tls_counters.n_tls_tx_records || p_si_stats->tls_counters.n_tls_tx_bytes) {
        fprintf(filename, "TLS Tx Offload: %" PRIu64 " / %u [kilobytes/records]%s\n",
                p_si_stats->tls_counters.n_tls_tx_bytes / BYTES_TRAFFIC_UNIT,
                p_si_stats->tls_counters.n_tls_tx_records, post_fix);
        b_any_activiy = true;
    }
    if (p_si_stats->tls_counters.n_tls_tx_resync ||
        p_si_stats->tls_counters.n_tls_tx_resync_replay) {
        fprintf(filename, "TLS Tx Resyncs: %u / %u [total/with data replay]%s\n",
                p_si_stats->tls_counters.n_tls_tx_resync,
                p_si_stats->tls_counters.n_tls_tx_resync_replay, post_fix);
    }

    if (p_si_stats->tls_counters.n_tls_rx_records || p_si_stats->tls_counters.n_tls_rx_bytes) {
        fprintf(filename,
                "TLS Rx Offload: %" PRIu64
                " / %u / %u / %u [kilobytes/records/encrypted/mixed]%s\n",
                p_si_stats->tls_counters.n_tls_rx_bytes / BYTES_TRAFFIC_UNIT,
                p_si_stats->tls_counters.n_tls_rx_records,
                p_si_stats->tls_counters.n_tls_rx_records_enc,
                p_si_stats->tls_counters.n_tls_rx_records_partial, post_fix);
        b_any_activiy = true;
    }
    if (p_si_stats->tls_counters.n_tls_rx_resync) {
        fprintf(filename, "TLS Rx Resyncs: %u [total]%s\n",
                p_si_stats->tls_counters.n_tls_rx_resync, post_fix);
    }
#endif /* DEFINED_UTLS */

    if (p_si_stats->tcp_state == LISTEN || p_si_stats->listen_counters.n_rx_syn) {
        fprintf(filename, "Listen Backlog: %u [current]\n",
                p_si_stats->listen_counters.n_conn_backlog);
        fprintf(
            filename, "Listen Accepts: %u / %u / %u / %u [accepted/established/SYNs/reused]%s\n",
            p_si_stats->listen_counters.n_conn_accepted,
            p_si_stats->listen_counters.n_conn_established, p_si_stats->listen_counters.n_rx_syn,
            p_si_stats->listen_counters.n_rx_syn_tw, post_fix);
        if (p_si_stats->listen_counters.n_conn_dropped != 0) {
            fprintf(filename, "Listen Errors: %u / %u [dropped/FINs]%s\n",
                    p_si_stats->listen_counters.n_conn_dropped,
                    p_si_stats->listen_counters.n_rx_fin, post_fix);
        }
        b_any_activiy = b_any_activiy || p_si_stats->listen_counters.n_conn_accepted ||
            p_si_stats->listen_counters.n_conn_established ||
            p_si_stats->listen_counters.n_rx_syn || p_si_stats->listen_counters.n_rx_syn_tw ||
            p_si_stats->listen_counters.n_conn_dropped;
    }

    if (b_any_activiy == false) {
        fprintf(filename, "Rx and Tx where not active\n");
    }
}

// Print statistics headers for all sockets - used in case view mode is e_netstat_like
void print_netstat_like_headers(FILE *file)
{
    static bool already_printed = false;
    if (!already_printed) {
        fprintf(file, "%-5s %-9s %-14s %-14s %-47s %-47s %-11s %-10s %s", "Proto", "Offloaded",
                "Recv-Q", "Send-Q", "Local Address", "Foreign Address", "State", "Inode",
                "PID/Program name\n");
    }
    already_printed = true;
}

// Print statistics of a single socket - used in case view mode is e_netstat_like
void print_netstat_like(socket_stats_t *p_si_stats, mc_grp_info_t *, FILE *file, int pid)
{
    static const int MAX_ADDR_LEN =
        strlen("[1234:1234:1234:1234:1234:1234:1234:1234]:12345"); // for max len of ip address and
                                                                   // port together
    char process[PATH_MAX + 1];

    if (!p_si_stats->inode) {
        return; // shmem is not updated yet
    }

    fprintf(file, "%-5s %-9s ",
            to_str_socket_type_netstat_like(p_si_stats->socket_type, p_si_stats->sa_family),
            p_si_stats->b_is_offloaded ? "Yes" : "No");
    fprintf(file, "%-14lu %-14lu ", p_si_stats->n_rx_ready_byte_count,
            p_si_stats->n_tx_ready_byte_count);

    //
    // Bounded + Connected information
    //
    int len = 0;
    if (!p_si_stats->bound_if.is_anyaddr() || p_si_stats->bound_port) {
        len = fprintf(file, "%s:%-5d", p_si_stats->bound_if.to_str(p_si_stats->sa_family).c_str(),
                      ntohs(p_si_stats->bound_port));

        if (len < 0) {
            len = 0; // error
        }
    }
    if (len <= MAX_ADDR_LEN) {
        fprintf(file, "%*s", MAX_ADDR_LEN - len, ""); // pad and delimiter
    }

    fprintf(file, " ");

    if (!p_si_stats->connected_ip.is_anyaddr() || p_si_stats->connected_port) {
        len =
            fprintf(file, "%s:%-5d", p_si_stats->connected_ip.to_str(p_si_stats->sa_family).c_str(),
                    ntohs(p_si_stats->connected_port));
    } else {
        if (p_si_stats->sa_family == AF_INET6) {
            len = fprintf(file, "[::]:*");
        } else {
            len = fprintf(file, "0.0.0.0:*");
        }
    }
    if (len < 0) {
        len = 0; // error
    }
    if (len <= MAX_ADDR_LEN) {
        fprintf(file, "%*s ", MAX_ADDR_LEN - len, ""); // pad and delimiter
    }

    const char *tcp_state = "";
    if (p_si_stats->socket_type == SOCK_STREAM) {
        tcp_state = tcp_state_str[((enum tcp_state)p_si_stats->tcp_state)];
    }

    fprintf(file, "%-11s %-10lu %d/%s\n", tcp_state, (u_long)p_si_stats->inode, pid,
            (get_procname(pid, process, sizeof(process)) == 0
                 ? process
                 : "-")); // max tcp state len is 11 characters = ESTABLISHED
}
