/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "utils.h"

#include <errno.h>
#include <sys/resource.h>
#include <string.h>
#include "core/util/if.h"
#include <sys/stat.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_addr.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef HAVE_LINUX_ETHTOOL_H
#include <linux/ethtool.h> // ioctl(SIOCETHTOOL)
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netlink/route/link.h>
#include <netlink/msg.h>

#include <array>
#include <iostream>
#include <limits>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "core/util/sys_vars.h"
#include "core/util/sock_addr.h"
#include "core/sock/sock-redirect.h"
#include "core/util/vtypes.h"
#include "core/ib/base/verbs_extra.h"

#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

using namespace std;

#undef MODULE_NAME
#define MODULE_NAME "utils:"

int check_if_regular_file(char *path)
{
    static struct stat __sys_st;

    if (stat(path, &__sys_st) == 0) {
        BULLSEYE_EXCLUDE_BLOCK_START
        if (!S_ISREG(__sys_st.st_mode)) {
            return -1;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
    }

    return 0;
}

int get_sys_max_fd_num(int def_max_fd /*=1024*/)
{
    struct rlimit rlim;
    BULLSEYE_EXCLUDE_BLOCK_START
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        return rlim.rlim_cur;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    return def_max_fd;
}

int get_base_interface_name(const char *if_name, char *base_ifname, size_t sz_base_ifname)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    if ((!if_name) || (!base_ifname)) {
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    memset(base_ifname, 0, sz_base_ifname);

    if (get_vlan_base_name_from_ifname(if_name, base_ifname, sz_base_ifname)) {
        return 0;
    }

    // Am I already the base (not virtual, not alias, can be bond)
    if ((!check_device_exist(if_name, VIRTUAL_DEVICE_FOLDER) || check_bond_device_exist(if_name)) &&
        !strstr(if_name, ":")) {
        snprintf(base_ifname, sz_base_ifname, "%s", if_name);
        return 0;
    }

    unsigned char vlan_if_address[MAX_L2_ADDR_LEN];
    const size_t ADDR_LEN = get_local_ll_addr(if_name, vlan_if_address, MAX_L2_ADDR_LEN, false);
    if (ADDR_LEN > 0) {
        struct ifaddrs *ifaddr, *ifa;
        int rc = getifaddrs(&ifaddr);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (rc == -1) {
            __log_err("getifaddrs failed");
            return -1;
        }
        BULLSEYE_EXCLUDE_BLOCK_END

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!strcmp(ifa->ifa_name, if_name)) {
                continue;
            }

            if (strstr(ifa->ifa_name, ":")) {
                // alias
                continue;
            }

            if (check_device_exist(ifa->ifa_name, VIRTUAL_DEVICE_FOLDER)) {
                // virtual
                if (!check_bond_device_exist(ifa->ifa_name)) {
                    continue;
                }
            }

            unsigned char tmp_mac[ADDR_LEN];
            if (ADDR_LEN == get_local_ll_addr(ifa->ifa_name, tmp_mac, ADDR_LEN, false)) {
                int size_to_compare = 0;
                if (ADDR_LEN == ETH_ALEN) {
                    size_to_compare = ETH_ALEN;
                }
                int offset = ADDR_LEN - size_to_compare;
                if (0 == memcmp(vlan_if_address + offset, tmp_mac + offset, size_to_compare) &&
                    0 == (ifa->ifa_flags & IFF_MASTER)) {
                    // A bond name cannot be a base name of an interface even if both have the same
                    // MAC(ethernet) or GID(IB) addresses
                    snprintf(base_ifname, sz_base_ifname, "%s", ifa->ifa_name);
                    freeifaddrs(ifaddr);
                    __log_dbg("Found base_ifname %s for interface %s", base_ifname, if_name);
                    return 0;
                }
            }
        }

        freeifaddrs(ifaddr);
    }
    snprintf(base_ifname, sz_base_ifname, "%s", if_name);
    return 0;
}

void print_roce_lag_warnings(const char *interface, char *disable_path /* = NULL */,
                             const char *port1 /* = NULL */, const char *port2 /* = NULL */)
{
    vlog_printf(VLOG_WARNING,
                "**********************************************************************************"
                "********************\n");

    if (port1 && port2) {
        vlog_printf(
            VLOG_WARNING,
            "* Bond %s has two slaves of the same device while RoCE LAG is enabled (%s, %s).\n",
            interface, port1, port2);
        vlog_printf(VLOG_WARNING, "* Unexpected behaviour may occur during runtime.\n");
    } else {
        vlog_printf(VLOG_WARNING, "* Interface %s will not be offloaded.\n", interface);
        vlog_printf(VLOG_WARNING,
                    "* " PRODUCT_NAME " cannot offload the device while RoCE LAG is enabled.\n");
    }

    vlog_printf(VLOG_WARNING, "* Please refer to " PRODUCT_NAME " Release Notes for more info\n");

    if (disable_path) {
        vlog_printf(VLOG_WARNING, "* In order to disable RoCE LAG please use:\n");
        vlog_printf(VLOG_WARNING, "* echo 0 > %s\n", disable_path);
    }
    vlog_printf(VLOG_WARNING,
                "**********************************************************************************"
                "********************\n");
}

void print_warning_rlimit_memlock(size_t length, int error)
{
    vlog_printf(VLOG_ERROR,
                "**********************************************************************************"
                "********************\n");
    vlog_printf(VLOG_ERROR, "* Failed registering a memory region of size %zu bytes\n", length);
    vlog_printf(VLOG_ERROR, "* (errno=%d %m)\n", error);
    vlog_printf(VLOG_ERROR, "* Could be due to lack of locked memory in kernel.\n");
    vlog_printf(VLOG_ERROR, "* Please check max allowed locked memory (ulimit -l)\n");
    vlog_printf(VLOG_ERROR,
                "**********************************************************************************"
                "********************\n");
}

void compute_tx_checksum(mem_buf_desc_t *p_mem_buf_desc, bool l3_csum, bool l4_csum)
{
    unsigned short l3_checksum = -1, l4_checksum = -1;

    if (l3_csum || l4_csum) {
        struct iphdr *ipv4 = p_mem_buf_desc->tx.p_ip4_h;
        bool is_ipv4 = (ipv4->version == 4);

        if (l3_csum && is_ipv4) {
            __log_dbg("Should not get here - IP checksum should be calculated by HW...");
            ipv4->check = 0;
            ipv4->check = l3_checksum = compute_ip_checksum(ipv4);
        }

        if (l4_csum) {
            struct ip6_hdr *ipv6 = p_mem_buf_desc->tx.p_ip6_h;
            uint8_t protocol = (is_ipv4) ? ipv4->protocol : ipv6->ip6_nxt;
            if (protocol == IPPROTO_UDP) {
                // UDP Checksum for IPv4 is not mandatory, so we set it to 0.
                struct udphdr *udp_hdr = p_mem_buf_desc->tx.p_udp_h;
                udp_hdr->check = 0;
                if (!is_ipv4) {
                    const uint16_t *udp_hdr_buf = reinterpret_cast<const uint16_t *>(udp_hdr);
                    udp_hdr->check = compute_udp_checksum_tx(ipv6, udp_hdr_buf, udp_hdr);
                }
                l4_checksum = udp_hdr->check;
            } else if (protocol == IPPROTO_TCP) {
                __log_dbg("Should not get here - TCP checksum should be calculated by HW...");
                struct tcphdr *tcp_hdr = p_mem_buf_desc->tx.p_tcp_h;
                const uint16_t *tcp_hdr_buf = reinterpret_cast<const uint16_t *>(tcp_hdr);
                tcp_hdr->check = 0;
                if (is_ipv4) {
                    l4_checksum = compute_tcp_checksum(ipv4, tcp_hdr_buf, ipv4->ihl << 2);
                } else {
                    l4_checksum = compute_tcp_checksum(ipv6, tcp_hdr_buf, 0U);
                }
                tcp_hdr->check = l4_checksum;
            } else if (protocol == IPPROTO_FRAGMENT) {
                if (!is_ipv4) {
                    // l4 SW checksum is enabled ONLY for IPv6 fragmented UDP packets
                    // sum for payload is done in dst_entry_udp since it requires the entire payload
                    // and it is stored in udp_hdr->check
                    struct udphdr *udp_hdr = p_mem_buf_desc->tx.p_udp_h;
                    udp_hdr->check = l4_checksum = compute_ipv6_udp_frag_checksum(ipv6, udp_hdr);
                }
            } else {
                __log_err("Could not calculate L4 SW checksum. next protocol: %d", protocol);
            }
        }
    }

    NOT_IN_USE(l4_checksum);
    NOT_IN_USE(l3_checksum);
    __log_entry_func("SW checksum calculation: L3 = %d, L4 = %d", l3_checksum, l4_checksum);
}

unsigned short compute_ip_checksum(const uint16_t *p_data, size_t sz_count)
{
    unsigned long sum = 0;

    while (sz_count--) {
        sum += *p_data;
        p_data++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

unsigned short compute_ip_checksum(const iphdr *p_ip_h)
{
    const unsigned short *buf = reinterpret_cast<const unsigned short *>(p_ip_h);
    unsigned int nshort_words = p_ip_h->ihl * 2;
    return compute_ip_checksum(buf, nshort_words);
}

unsigned short compute_ip_checksum(const ip6_hdr *p_ip_h)
{
    (void)p_ip_h;
    return 0;
}

static uint32_t compute_pseudo_header(const iphdr *ipv4, uint16_t proto, uint16_t proto_len)
{
    uint32_t sum = ((ipv4->saddr >> 16) & 0xFFFF) + ((ipv4->saddr) & 0xFFFF) +
        ((ipv4->daddr >> 16) & 0xFFFF) + ((ipv4->daddr) & 0xFFFF) + htons(proto) + htons(proto_len);
    return sum;
}

static uint32_t compute_pseudo_header(const ip6_hdr *ipv6, uint16_t proto, uint16_t proto_len)
{
    const uint16_t *saddr = ipv6->ip6_src.s6_addr16;
    const uint16_t *daddr = ipv6->ip6_dst.s6_addr16;

    uint32_t sum = saddr[0] + saddr[1] + saddr[2] + saddr[3] + saddr[4] + saddr[5] + saddr[6] +
        saddr[7] + daddr[0] + daddr[1] + daddr[2] + daddr[3] + daddr[4] + daddr[5] + daddr[6] +
        daddr[7] + htons(proto) + htons(proto_len);
    return sum;
}

/*
 * get tcp checksum: given IP header and tcp segment (assume checksum field in TCP header contains
 * zero) matches RFC 793
 *
 * This code borrows from other places and their ideas.
 * */
static unsigned short compute_payload_checksum(const uint16_t *payload, uint16_t payload_len,
                                               uint32_t sum)
{
    while (payload_len > 1) {
        sum += *payload++;
        payload_len -= 2;
    }

    if (payload_len > 0) {
        sum += ((*payload) & htons(0xFF00));
    }
    //
    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = ~sum;
    return static_cast<unsigned short>(sum);
}

unsigned short compute_tcp_checksum(const iphdr *ipv4, const uint16_t *payload, uint16_t hdr_len)
{
    uint16_t tcpLen = ntohs(ipv4->tot_len) - hdr_len;
    uint32_t sum = compute_pseudo_header(ipv4, IPPROTO_TCP, tcpLen);
    return compute_payload_checksum(payload, tcpLen, sum);
}

unsigned short compute_tcp_checksum(const ip6_hdr *ipv6, const uint16_t *payload,
                                    uint16_t ext_hdr_len)
{
    uint16_t tcpLen = ntohs(ipv6->ip6_plen) - ext_hdr_len;
    uint32_t sum = compute_pseudo_header(ipv6, IPPROTO_TCP, tcpLen);
    return compute_payload_checksum(payload, tcpLen, sum);
}

unsigned short compute_udp_checksum_tx(const ip6_hdr *ipv6, const uint16_t *payload, udphdr *udp)
{
    uint16_t ipLen = ntohs(ipv6->ip6_plen);
    uint32_t sum = compute_pseudo_header(ipv6, IPPROTO_UDP, ntohs(udp->len));

    // For UDP, checksum zero means no checksum. Zero must be replaced with 0xffff.
    return compute_payload_checksum(payload, ipLen, sum) ?: 0xffff;
}

/*
 * UDP checksum is mandatory for IPv6, see calculation in RFC 2460.
 * data sum is placed temporary in udp->check field.
 * after checksum calculation - this field will be updated.
 * */
unsigned short compute_ipv6_udp_frag_checksum(const ip6_hdr *ipv6, udphdr *udp)
{
    uint32_t sum = udp->check;
    sum += compute_pseudo_header(ipv6, IPPROTO_UDP, ntohs(udp->len));
    sum += udp->source + udp->dest + udp->len;

    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // For UDP, checksum zero means no checksum. Zero must be replaced with 0xffff.
    if (sum != 0xffff) {
        sum = ~sum;
    }

    return static_cast<unsigned short>(sum);
}

unsigned short compute_udp_payload_checksum_rx(const struct udphdr *udphdrp,
                                               mem_buf_desc_t *p_rx_wc_buf_desc, uint16_t udp_len,
                                               uint32_t sum)
{
    const uint16_t *p_ip_payload = (const uint16_t *)udphdrp;
    mem_buf_desc_t *p_ip_frag = p_rx_wc_buf_desc;
    unsigned short ip_frag_len = p_ip_frag->rx.frag.iov_len + sizeof(struct udphdr);
    unsigned short ip_frag_remainder = ip_frag_len;

    // add the IP payload
    while (udp_len > 1) {
        // Each packet but the last must contain a payload length that is a multiple of 8
        if (!ip_frag_remainder && p_ip_frag->p_next_desc) {
            p_ip_frag = p_ip_frag->p_next_desc;
            p_ip_payload = (const uint16_t *)p_ip_frag->rx.frag.iov_base;
            ip_frag_remainder = ip_frag_len = p_ip_frag->rx.frag.iov_len;
        }

        while (ip_frag_remainder > 1) {
            sum += *p_ip_payload++;
            ip_frag_remainder -= 2;
        }

        udp_len -= (ip_frag_len - ip_frag_remainder);
    }

    // if any bytes left, pad the bytes and add
    if (udp_len > 0) {
        sum += ((*p_ip_payload) & htons(0xFF00));
    }

    // Fold sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = ~sum;
    // computation result
    return (unsigned short)sum;
}

/* set udp checksum: given IP header and UDP datagram
 *
 * (assume checksum field in UDP header contains zero)
 * This code borrows from other places and their ideas.
 * Although according to rfc 768, If the computed checksum is zero, it is transmitted as all ones -
 * this method will return the original value.
 */
unsigned short compute_udp_checksum_rx(const struct iphdr *ip_hdr, const struct udphdr *udphdrp,
                                       mem_buf_desc_t *p_rx_wc_buf_desc)
{
    uint16_t udp_len = ntohs(udphdrp->len);
    uint32_t sum = compute_pseudo_header(ip_hdr, IPPROTO_UDP, udp_len);
    return compute_udp_payload_checksum_rx(udphdrp, p_rx_wc_buf_desc, udp_len, sum);
}

unsigned short compute_udp_checksum_rx(const struct ip6_hdr *ip_hdr, const struct udphdr *udphdrp,
                                       mem_buf_desc_t *p_rx_wc_buf_desc)
{
    uint16_t udp_len = ntohs(udphdrp->len);
    uint32_t sum = compute_pseudo_header(ip_hdr, IPPROTO_UDP, udp_len);
    return compute_udp_payload_checksum_rx(udphdrp, p_rx_wc_buf_desc, udp_len, sum);
}

/**
 * Copy iovec to buffer
 * Returns total bytes copyed
 */
int memcpy_fromiovec(u_int8_t *p_dst, const struct iovec *p_iov, size_t sz_iov,
                     size_t sz_src_start_offset, size_t sz_data)
{
    /* Skip to start offset  */
    int n_iovpos = 0;
    while (n_iovpos < (int)sz_iov && sz_src_start_offset >= p_iov[n_iovpos].iov_len) {
        sz_src_start_offset -= p_iov[n_iovpos].iov_len;
        n_iovpos++;
    }

    /* Copy len size into pBuf */
    int n_total = 0;
    while (n_iovpos < (int)sz_iov && sz_data > 0) {
        if (likely(p_iov[n_iovpos].iov_len) && likely(p_iov[n_iovpos].iov_base)) {
            u_int8_t *p_src = ((u_int8_t *)(p_iov[n_iovpos].iov_base)) + sz_src_start_offset;
            int sz_data_block_to_copy = min(sz_data, p_iov[n_iovpos].iov_len - sz_src_start_offset);
            sz_src_start_offset = 0;

            memcpy(p_dst, p_src, sz_data_block_to_copy);

            p_dst += sz_data_block_to_copy;
            sz_data -= sz_data_block_to_copy;
            n_total += sz_data_block_to_copy;
        }
        n_iovpos++;
    }
    return n_total;
}

void set_fd_block_mode(int fd, bool b_block)
{
    __log_dbg("fd[%d]: setting to %sblocking mode (%d)", fd, b_block ? "" : "non-", b_block);

    int flags = orig_os_api.fcntl(fd, F_GETFL);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (flags < 0) {
        __log_err("failed reading fd[%d] flag (rc=%d errno=%d %m)", fd, flags, errno);
        return;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (b_block) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }

    int ret = orig_os_api.fcntl(fd, F_SETFL, flags);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (ret < 0) {
        __log_err("failed changing fd[%d] to %sblocking mode (rc=%d errno=%d %s)", fd,
                  b_block ? "" : "non-", ret, errno, strerror(errno));
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    return;
}

bool compare_double(double a, double b)
{
    return fabs(a - b) < std::numeric_limits<double>::epsilon();
}

const char *iphdr_protocol_type_to_str(const int type)
{
    BULLSEYE_EXCLUDE_BLOCK_START
    switch (type) {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    default:
        break;
    }
    return "Not supported";
    BULLSEYE_EXCLUDE_BLOCK_END
}

int priv_read_file(const char *path, char *buf, size_t size,
                   vlog_levels_t log_level /*= VLOG_ERROR*/)
{
    int len = -1;
    int fd = open(path, O_RDONLY);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (fd < 0) {
        VLOG_PRINTF(log_level, "ERROR while opening file %s (errno %d %m)", path, errno);
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    len = read(fd, buf, size);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (len < 0) {
        VLOG_PRINTF(log_level, "ERROR while reading from file %s (errno %d %m)", path, errno);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    close(fd);
    return len;
}

int read_file_to_int(const char *path, int default_value, vlog_levels_t log_level)
{
    char buf[25];
    int rc = priv_safe_read_file(path, buf, sizeof buf, log_level);
    if (rc < 0) {
        VLOG_PRINTF(log_level, "ERROR while getting int from from file %s, we'll use default %d",
                    path, default_value);
    }
    return (rc < 0) ? default_value : atoi(buf);
}

int get_port_from_ifname(const char *ifname)
{
    int port_num, dev_id = -1, dev_port = -1;
    // Depending of kernel version and OFED stack the files containing dev_id and dev_port may not
    // exist. if file reading fails *dev_id or *dev_port may remain unmodified
    char num_buf[24] = {0};
    char dev_path[256] = {0};
    snprintf(dev_path, sizeof(dev_path), VERBS_DEVICE_PORT_PARAM_FILE, ifname);
    if (priv_safe_try_read_file(dev_path, num_buf, sizeof(num_buf)) > 0) {
        dev_port =
            strtol(num_buf, NULL, 0); // base=0 means strtol() can parse hexadecimal and decimal
        __log_dbg("dev_port file=%s dev_port str=%s dev_port val=%d", dev_path, num_buf, dev_port);
    }
    snprintf(dev_path, sizeof(dev_path), VERBS_DEVICE_ID_PARAM_FILE, ifname);
    if (priv_safe_try_read_file(dev_path, num_buf, sizeof(num_buf)) > 0) {
        dev_id =
            strtol(num_buf, NULL, 0); // base=0 means strtol() can parse hexadecimal and decimal
        __log_dbg("dev_id file= %s dev_id str=%s dev_id val=%d", dev_path, num_buf, dev_id);
    }

    // take the max between dev_port and dev_id as port number
    port_num = (dev_port > dev_id) ? dev_port : dev_id;
    return ++port_num;
}

int get_iftype_from_ifname(const char *ifname)
{
    __log_func("find interface type for ifname '%s'", ifname);

    char iftype_filename[100];
    char iftype_value_str[32];
    char base_ifname[32];
    char iftype_value = -1;

    get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
    sprintf(iftype_filename, IFTYPE_PARAM_FILE, base_ifname);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (priv_read_file(iftype_filename, iftype_value_str, sizeof(iftype_value_str)) > 0) {
        iftype_value = atoi(iftype_value_str);
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    return iftype_value;
}

int get_if_mtu_from_ifname(const char *ifname)
{
    __log_func("find interface mtu for ifname '%s'", ifname);

    char if_mtu_len_filename[100];
    char if_mtu_value_str[32];
    char base_ifname[32];
    int if_mtu_value = 0;

    /* initially try reading MTU from ifname. In case of failure (expected in alias ifnames) - try
     * reading MTU from base ifname */
    sprintf(if_mtu_len_filename, IFADDR_MTU_PARAM_FILE, ifname);

    if (priv_safe_try_read_file(if_mtu_len_filename, if_mtu_value_str, sizeof(if_mtu_value_str)) >
        0) {
        if_mtu_value = atoi(if_mtu_value_str);
    } else {
        get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
        sprintf(if_mtu_len_filename, IFADDR_MTU_PARAM_FILE, base_ifname);
        if (priv_safe_try_read_file(if_mtu_len_filename, if_mtu_value_str,
                                    sizeof(if_mtu_value_str)) > 0) {
            if_mtu_value = atoi(if_mtu_value_str);
        }
    }
    return if_mtu_value;
}

int get_window_scaling_factor(int tcp_rmem_max, int core_rmem_max)
{
    __log_func("calculate OS tcp scaling window factor");

    int scaling_factor = 0;
    int space = std::max(tcp_rmem_max, core_rmem_max);

    while (space > 0xffff && scaling_factor < MAX_WINDOW_SCALING) {
        space >>= 1;
        scaling_factor++;
    }

    __log_dbg("TCP scaling window factor is set to %d", scaling_factor);
    return scaling_factor;
}

using netlink_buffer = std::array<uint8_t, 4096>;

class socket_context_manager {
    int m_fd;
    netlink_buffer m_buf;

public:
    socket_context_manager()
    {
        struct timeval tv = {
            .tv_sec = 0,
            .tv_usec = 10,
        };

        m_fd = orig_os_api.socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (m_fd < 0) {
            throw std::runtime_error("Open netlink socket failed");
        }

        if (orig_os_api.setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv)) {
            close(m_fd);
            throw std::runtime_error("Setsockopt non-blocking failed");
        }
    }

    socket_context_manager(int fd) noexcept
        : m_fd(fd) {};
    ~socket_context_manager() { close(m_fd); };

    void send_getaddr_request(uint8_t family)
    {
        sockaddr_nl sa = {AF_NETLINK, 0, 0, 0};
        struct {
            nlmsghdr nl;
            ifaddrmsg addrmsg;
        } msg_buf {
            {
                NLMSG_LENGTH(sizeof(ifaddrmsg)),
                RTM_GETADDR,
                NLM_F_REQUEST | NLM_F_ROOT,
                0,
                0,
            },
            {family, 0, 0, 0, 0},
        };

        iovec iov = {&msg_buf, msg_buf.nl.nlmsg_len};
        msghdr msg = {&sa, sizeof(sa), &iov, 1, nullptr, 0, 0};

        if (orig_os_api.sendmsg(m_fd, &msg, 0) < 0) {
            throw std::runtime_error("Send RTM_GETADDR request failed");
        }
    }

    int recv_response()
    {
        sockaddr_nl sa = {AF_NETLINK, 0, 0, 0};
        iovec iov = {&m_buf, m_buf.size()};
        msghdr msg = {&sa, sizeof(sa), &iov, 1, nullptr, 0, 0};

        return orig_os_api.recvmsg(m_fd, &msg, 0);
    }

    nlmsghdr *get_nlmsghdr() { return reinterpret_cast<nlmsghdr *>(&m_buf); }
};

int get_ip_addr_from_ifindex(uint32_t ifindex, ip_addr &addr, sa_family_t family)
{
    try {
        auto socket_cm = socket_context_manager();
        socket_cm.send_getaddr_request(family);

        do {
            int len = socket_cm.recv_response();
            if (len < 0) {
                throw std::runtime_error("recv_response failed");
            }

            for (auto nl = socket_cm.get_nlmsghdr(); nlmsg_ok(nl, len); nl = nlmsg_next(nl, &len)) {
                struct ifaddrmsg *ifa = reinterpret_cast<struct ifaddrmsg *>(nlmsg_data(nl));
                if (ifa->ifa_index != ifindex || ifa->ifa_family != family ||
                    nl->nlmsg_type != RTM_NEWADDR) {
                    continue;
                }

                uint32_t rta_len = IFA_PAYLOAD(nl);
                for (auto rta = IFA_RTA(ifa); RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                    if (rta->rta_type != IFA_ADDRESS) {
                        continue;
                    }
                    addr = (family == AF_INET)
                        ? ip_addr(*reinterpret_cast<in_addr *>(RTA_DATA(rta)), AF_INET)
                        : ip_addr(*reinterpret_cast<in6_addr *>(RTA_DATA(rta)), AF_INET6);
                    return 0;
                }
            }
        } while (true);
    } catch (std::runtime_error &e) {
        __log_dbg("Failed getting ip from interface #%d - %s", ifindex, e.what());
        return -1;
    }
    return 0;
}

int get_ip_addr_from_ifname(const char *ifname, ip_addr &addr, sa_family_t family)
{
    __log_func("find ip addr for ifname '%s'", ifname);

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        __log_err("ERROR no interface with the %s name (errno=%d)", ifname, errno);
        return -1;
    }
    return get_ip_addr_from_ifindex(ifindex, addr, family);
}

uint16_t ipv6_addr_type_scope(const ip_address &addr, uint8_t &scope)
{
    uint16_t up16 = ntohs(reinterpret_cast<const uint16_t *>(&addr.get_in6_addr())[0]);

    // Consider all addresses with the first three bits different of 000 and 111 as unicasts.
    if ((up16 & 0xE000) != 0U && (up16 & 0xE000) != 0xE000) {
        scope = IPV6_ADDR_SCOPE_GLOBAL;
        return IPV6_ADDR_UNICAST;
    }

    if ((up16 & 0xFF00) == 0xFF00) { // Multicast, addr-select 3.1
        scope = up16 & IPV6_ADDR_SCOPE_MASK;
        return IPV6_ADDR_MULTICAST;
    }

    if ((up16 & 0xFFC0) == 0xFE80) { // addr-select 3.1
        scope = IPV6_ADDR_SCOPE_LINKLOCAL;
        return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST);
    }

    if ((up16 & 0xFFC0) == 0xFEC0) { // addr-select 3.1
        scope = IPV6_ADDR_SCOPE_SITELOCAL;
        return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST);
    }

    if ((up16 & 0xFE00) == 0xFC00) { // RFC 4193
        scope = IPV6_ADDR_SCOPE_GLOBAL;
        return IPV6_ADDR_UNICAST;
    }

    const uint32_t *addr32 = reinterpret_cast<const uint32_t *>(&addr.get_in6_addr());
    if ((addr32[0] | addr32[1]) == 0) {
        if (addr32[2] == 0) {
            if (addr32[3] == 0) {
                scope = 0U;
                return IPV6_ADDR_ANY;
            }

            if (addr32[3] == 0x01000000) { // 0x01000000 = htonl(0x00000001)
                scope = IPV6_ADDR_SCOPE_LINKLOCAL;
                return (IPV6_ADDR_LOOPBACK | IPV6_ADDR_UNICAST); // addr-select 3.4
            }

            scope = IPV6_ADDR_SCOPE_GLOBAL;
            return (IPV6_ADDR_COMPATv4 | IPV6_ADDR_UNICAST); // addr-select 3.3
        }

        if (addr32[2] == 0xffff0000) { // 0xffff0000 = htonl(0x0000ffff)
            scope = IPV6_ADDR_SCOPE_GLOBAL;
            return IPV6_ADDR_MAPPED; // addr-select 3.3
        }
    }

    scope = IPV6_ADDR_SCOPE_GLOBAL;
    return IPV6_ADDR_UNICAST; // addr-select 3.4
}

uint16_t get_vlan_id_from_ifname(const char *ifname)
{
    // find vlan id from interface name
    struct vlan_ioctl_args ifr;
    int fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) {
        __log_err("ERROR from socket() (errno=%d %m)", errno);
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.cmd = GET_VLAN_VID_CMD;
    strncpy(ifr.device1, ifname, sizeof(ifr.device1) - 1);

    if (orig_os_api.ioctl(fd, SIOCGIFVLAN, &ifr) < 0) {
        __log_dbg(
            "Failure in ioctl(SIOCGIFVLAN, cmd=GET_VLAN_VID_CMD) for interface '%s' (errno=%d %m)",
            ifname, errno);
        orig_os_api.close(fd);
        return 0;
    }

    orig_os_api.close(fd);

    __log_dbg("found vlan id '%d' for interface '%s'", ifr.u.VID, ifname);

    return ifr.u.VID;
}

size_t get_vlan_base_name_from_ifname(const char *ifname, char *base_ifname, size_t sz_base_ifname)
{
    // find vlan base name from interface name
    struct vlan_ioctl_args ifr;
    int fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        __log_err("ERROR from socket() (errno=%d %m)", errno);
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.cmd = GET_VLAN_REALDEV_NAME_CMD;
    strncpy(ifr.device1, ifname, sizeof(ifr.device1) - 1);

    if (orig_os_api.ioctl(fd, SIOCGIFVLAN, &ifr) < 0) {
        __log_dbg("Failure in ioctl(SIOCGIFVLAN, cmd=GET_VLAN_REALDEV_NAME_CMD) for interface '%s' "
                  "(errno=%d %m)",
                  ifname, errno);
        orig_os_api.close(fd);
        return 0;
    }

    orig_os_api.close(fd);

    size_t name_len = strlen(ifr.u.device2);
    if (base_ifname && name_len > 0) {
        __log_dbg("found vlan base name '%s' for interface '%s'", ifr.u.device2, ifname);
        strncpy(base_ifname, ifr.u.device2, sz_base_ifname);
        return name_len;
    }

    __log_dbg("did not find vlan base name for interface '%s'", ifname);

    return 0;
}

int run_and_retreive_system_command(const char *cmd_line, char *return_str, int return_str_len)
{
    // TODO: NOTICE the current code will change the environment for all threads of our process

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!cmd_line) {
        return -1;
    }
    if (return_str_len <= 0) {
        return -1;
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    // Load dynamically
    for (int i = 0; environ[i]; i++) {
        if (strstr(environ[i], "LD_PRELOAD=")) {
            environ[i][0] = '_';
        }
    }

    // run system command and get response from FILE*
    int rc = -1;

    FILE *file = popen(cmd_line, "r");
    if (file) {
        int fd = fileno(file);
        if (fd > 0) {
            int actual_len = read(fd, return_str, return_str_len - 1);
            if (actual_len > 0) {
                return_str[actual_len] = '\0';
            } else {
                return_str[0] = '\0';
            }
        }

        // Check exit status code
        rc = pclose(file);
        if (rc == -1 && errno == ECHILD) {
            /* suppress a case when termination status can be unavailable to pclose() */
            rc = 0;
        }

        for (int i = 0; environ[i]; i++) {
            if (strstr(environ[i], "_D_PRELOAD=")) {
                environ[i][0] = 'L';
            }
        }
    }
    return ((!rc && return_str) ? 0 : -1);
}

size_t get_local_ll_addr(IN const char *ifname, OUT unsigned char *addr, IN int addr_len,
                         bool is_broadcast)
{
    char l2_addr_path[256] = {0};
    char buf[256] = {0};

    // In case of alias (ib0/eth0:xx) take only the device name for that interface (ib0/eth0)
    size_t ifname_len = strcspn(ifname, ":"); // TODO: this is temp code till we get base interface
                                              // for any alias format of an interface
    const char *l2_addr_path_fmt = is_broadcast ? L2_BR_ADDR_FILE_FMT : L2_ADDR_FILE_FMT;
    snprintf(l2_addr_path, sizeof(l2_addr_path) - 1, l2_addr_path_fmt, ifname_len, ifname);

    int len = priv_read_file(l2_addr_path, buf, sizeof(buf));
    int bytes_len =
        (len + 1) / 3; // convert len from semantic of hex format L2 address with ':' delimiter (and
                       // optional newline character) into semantic of byte array
    __log_dbg("ifname=%s un-aliased-ifname=%zu l2_addr_path=%s l2-addr=%s (addr-bytes_len=%d)",
              ifname, ifname_len, ifname, l2_addr_path, bytes_len);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (len < 0) {
        return 0; // failure in priv_read_file
    }
    if (addr_len < bytes_len) {
        return 0; // error not enough room was provided by caller
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    if (bytes_len == ETH_ALEN) {
        if (6 == sscanf(buf, ETH_HW_ADDR_SSCAN_FMT, ETH_HW_ADDR_SSCAN(addr))) {
            __log_dbg("found ETH %s address" ETH_HW_ADDR_PRINT_FMT " for interface %s",
                      is_broadcast ? "BR" : "UC", ETH_HW_ADDR_PRINT_ADDR(addr), ifname);
        }
    } else {
        return 0; // error
    }

    return bytes_len; // success
}

bool check_bond_device_exist(const char *ifname)
{
    int ret = 0;
    struct nl_cache *cache = NULL;
    struct rtnl_link *link = NULL;
    char *link_type = NULL;

    struct nl_sock *nl_socket = nl_socket_alloc();
    if (!nl_socket) {
        goto out;
    }
    nl_socket_set_local_port(nl_socket, 0);
    ret = nl_connect(nl_socket, NETLINK_ROUTE);
    if (ret < 0) {
        goto out;
    }
    ret = rtnl_link_alloc_cache(nl_socket, AF_UNSPEC, &cache);
    if (!cache || (ret < 0)) {
        goto out;
    }
    link = rtnl_link_get_by_name(cache, ifname);
    if (!link) {
        goto out;
    }
    link_type = rtnl_link_get_type(link);
    if (link_type && (strcmp(link_type, "bond") != 0)) {
        link_type = NULL;
    }
out:
    if (link) {
        rtnl_link_put(link);
    }
    if (cache) {
        nl_cache_free(cache);
    }
    if (nl_socket) {
        nl_socket_free(nl_socket);
    }

    return ((bool)link_type);
}

bool get_bond_name(IN const char *ifname, OUT char *bond_name, IN int sz)
{
    char upper_path[256];
    char base_ifname[IFNAMSIZ];
    get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
    struct ifaddrs *ifaddr, *ifa;
    bool ret = false;

    if (getifaddrs(&ifaddr) == -1) {
        __log_err("getifaddrs() failed (errno = %d %m)", errno);
        return ret;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        snprintf(upper_path, sizeof(upper_path), NETVSC_DEVICE_UPPER_FILE, base_ifname,
                 ifa->ifa_name);
        int fd = open(upper_path, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            if (IFNAMSIZ <= sz) {
                memcpy(bond_name, ifa->ifa_name, IFNAMSIZ);
            }
            ret = true;
            break;
        }
    }

    freeifaddrs(ifaddr);

    return ret;
}

bool get_bond_active_slave_name(IN const char *bond_name, OUT char *active_slave_name, IN int sz)
{
    char active_slave_path[256] = {0};
    sprintf(active_slave_path, BONDING_ACTIVE_SLAVE_PARAM_FILE, bond_name);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (priv_safe_read_file(active_slave_path, active_slave_name, sz) < 0) {
        return false;
    }
    if (strlen(active_slave_name) == 0) {
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    char *p = strchr(active_slave_name, '\n');
    if (p) {
        *p = '\0'; // Remove the tailing 'new line" char
    }
    return true;
}

bool check_bond_roce_lag_exist(OUT char *bond_roce_lag_path, int sz, IN const char *slave_name)
{
#if defined(DEFINED_DIRECT_VERBS) && defined(DEFINED_VERBS_VERSION) && (DEFINED_VERBS_VERSION == 3)
    NOT_IN_USE(bond_roce_lag_path);
    NOT_IN_USE(sz);
    NOT_IN_USE(slave_name);
    return true;
#endif

    return false;
}

bool get_netvsc_slave(IN const char *ifname, OUT char *slave_name, OUT unsigned int &slave_flags)
{
    char netvsc_path[256];
    char base_ifname[IFNAMSIZ];
    get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
    struct ifaddrs *ifaddr, *ifa;
    bool ret = false;

    if (getifaddrs(&ifaddr) == -1) {
        __log_err("getifaddrs() failed (errno = %d %m)", errno);
        return ret;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        snprintf(netvsc_path, sizeof(netvsc_path), NETVSC_DEVICE_LOWER_FILE, base_ifname,
                 ifa->ifa_name);
        int fd = open(netvsc_path, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            memcpy(slave_name, ifa->ifa_name, IFNAMSIZ);
            slave_flags = ifa->ifa_flags;
            __log_dbg("Found slave_name = %s, slave_flags = %u", slave_name, slave_flags);
            ret = true;
            break;
        }
    }

    freeifaddrs(ifaddr);

    return ret;
}

bool check_netvsc_device_exist(const char *ifname)
{
    int ret = -1;
    char device_path[256] = {0};
    char base_ifname[IFNAMSIZ];
    get_base_interface_name(ifname, base_ifname, sizeof(base_ifname));
    sprintf(device_path, NETVSC_DEVICE_CLASS_FILE, base_ifname);
    char sys_res[1024] = {0};
    if ((ret = priv_read_file(device_path, sys_res, sizeof(sys_res) - 1, VLOG_FUNC)) > 0) {
        sys_res[ret] = '\0';
        if (strcmp(sys_res, NETVSC_ID) == 0) {
            return true;
        }
    }

    return false;
}

/*
 * this function will work only for kernel  > 3.14 or RH7.2 and higher
 */
bool get_bond_slave_state(IN const char *slave_name, OUT char *curr_state, IN int sz)
{
    char bond_slave_state_path[256] = {0};
    sprintf(bond_slave_state_path, BONDING_SLAVE_STATE_PARAM_FILE, slave_name);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (priv_safe_try_read_file(bond_slave_state_path, curr_state, sz) < 0) {
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    char *p = strchr(curr_state, '\n');
    if (p) {
        *p = '\0'; // Remove the tailing 'new line" char
    }
    return true;
}

bool get_bond_slaves_name_list(IN const char *bond_name, OUT char *slaves_list, IN int sz)
{
    char slaves_list_path[256] = {0};
    sprintf(slaves_list_path, BONDING_SLAVES_PARAM_FILE, bond_name);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (priv_safe_read_file(slaves_list_path, slaves_list, sz) < 0) {
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    char *p = strchr(slaves_list, '\n');
    if (p) {
        *p = '\0'; // Remove the tailing 'new line" char
    }
    return true;
}

bool check_device_exist(const char *ifname, const char *path)
{
    char device_path[256] = {0};
    int fd = -1;
    int n = -1;

    n = snprintf(device_path, sizeof(device_path), path, ifname);
    if (likely((0 < n) && (n < (int)sizeof(device_path)))) {
        fd = orig_os_api.open(device_path, O_RDONLY);
        if (fd >= 0) {
            orig_os_api.close(fd);
        }
        if (fd < 0 && errno == EMFILE) {
            __log_warn("There are no free fds in the system. This may cause unexpected behavior");
        }
    }

    return (fd > 0);
}

bool check_device_name_ib_name(const char *ifname, const char *ibname)
{
    int n = -1;
    int fd = -1;
    char ib_path[IBV_SYSFS_PATH_MAX] = {0};
    const char *str_ifname = ifname;

    /* Case #1:
     * Direct mapping between if device and ib device
     * For example: ens4f1 -> mlx5_3
     */
    n = snprintf(ib_path, sizeof(ib_path), "/sys/class/infiniband/%s/device/net/%s/ifindex", ibname,
                 str_ifname);
    if (likely((0 < n) && (n < (int)sizeof(ib_path)))) {
        fd = open(ib_path, O_RDONLY);
        if (fd >= 0) {
            close(fd);
            return true;
        }
    }

#if (defined(DEFINED_DIRECT_VERBS) && defined(DEFINED_VERBS_VERSION) &&                            \
     (DEFINED_VERBS_VERSION == 3))
    /* Case #2:
     * When device is a slave interface
     * For example: ens4f1(bondX) -> mlx5_bond_X
     */
    char buf[IFNAMSIZ];

    if (get_bond_name(str_ifname, buf, sizeof(buf)) && strstr(ibname, "bond")) {
        str_ifname = buf;

        /* Case #3:
         * When device is a bonding interface
         * For example: bondX -> mlx5_bond_X
         */
        n = snprintf(ib_path, sizeof(ib_path), "/sys/class/infiniband/%s/ports/1/gid_attrs/ndevs/0",
                     ibname);
        if (likely((0 < n) && (n < (int)sizeof(ib_path)))) {
            int ret = -1;
            char sys_res[1024] = {0};
            if ((ret = priv_read_file(ib_path, sys_res, sizeof(sys_res) - 1, VLOG_FUNC)) > 0) {
                sys_res[ret] = '\0';
                char *p = strchr(sys_res, '\n');
                if (p) {
                    *p = '\0'; // Remove the tailing 'new line" char
                }
                if (strcmp(sys_res, str_ifname) == 0) {
                    return true;
                }
            }
        }
    }
#endif

    return false;
}

bool get_interface_oper_state(IN const char *interface_name, OUT char *curr_state, IN int sz)
{
    char interface_state_path[256] = {0};
    sprintf(interface_state_path, OPER_STATE_PARAM_FILE, interface_name);
    BULLSEYE_EXCLUDE_BLOCK_START
    if (priv_safe_read_file(interface_state_path, curr_state, sz) < 0) {
        return false;
    }
    BULLSEYE_EXCLUDE_BLOCK_END
    char *p = strchr(curr_state, '\n');
    if (p) {
        *p = '\0'; // Remove the tailing 'new line" char
    }
    return true;
}

bool validate_user_has_cap_net_raw_privliges()
{
#ifdef HAVE_SYS_CAPABILITY_H
    struct __user_cap_header_struct cap_header;
    cap_user_header_t cap_header_ptr = &cap_header;
    struct __user_cap_data_struct cap_data;
    cap_user_data_t cap_data_ptr = &cap_data;
    cap_header_ptr->pid = getpid();
    cap_header_ptr->version = _LINUX_CAPABILITY_VERSION;
    if (capget(cap_header_ptr, cap_data_ptr) < 0) {
        __log_dbg("error getting cap_net_raw permissions (%d %m)", errno);
        return false;
    } else {
        __log_dbg("successfully got cap_net_raw permissions. Effective=%X Permitted=%X",
                  cap_data_ptr->effective, cap_data_ptr->permitted);
    }
    return ((cap_data_ptr->effective & CAP_TO_MASK(CAP_NET_RAW)) != 0);
#else
    __log_dbg("libcap-devel library is not installed, skipping cap_net_raw permission checks");
    return false;
#endif
}

int validate_tso(int if_index)
{
#ifdef HAVE_LINUX_ETHTOOL_H
    int ret = -1;
    int fd = -1;
    struct ifreq req;
    struct ethtool_value eval;

    fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        __log_err("ERROR from socket() (errno=%d %m)", errno);
        return -1;
    }
    memset(&req, 0, sizeof(req));
    eval.cmd = ETHTOOL_GTSO;
    req.ifr_ifindex = if_index;
    if_indextoname(if_index, req.ifr_name);
    req.ifr_data = (char *)&eval;
    ret = orig_os_api.ioctl(fd, SIOCETHTOOL, &req);
    if (ret < 0) {
        __log_dbg("ioctl(SIOCETHTOOL) cmd=ETHTOOL_GTSO (errno=%d %m)", errno);
    } else {
        ret = eval.data;
    }
    orig_os_api.close(fd);
    return ret;
#else
    NOT_IN_USE(if_index);
    return -1;
#endif
}

int validate_lro(int if_index)
{
#ifdef HAVE_LINUX_ETHTOOL_H
    int ret = -1;
    int fd = -1;
    struct ifreq req;
    struct ethtool_value eval;

    fd = orig_os_api.socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        __log_err("ERROR from socket() (errno=%d %m)", errno);
        return -1;
    }
    memset(&req, 0, sizeof(req));
    eval.cmd = ETHTOOL_GFLAGS;
    req.ifr_ifindex = if_index;
    if_indextoname(if_index, req.ifr_name);
    req.ifr_data = (char *)&eval;
    ret = orig_os_api.ioctl(fd, SIOCETHTOOL, &req);
    if (ret < 0) {
        __log_dbg("ioctl(SIOCETHTOOL) cmd=ETHTOOL_GFLAGS (errno=%d %m)", errno);
    } else {
        ret = (eval.data & ETH_FLAG_LRO ? 1 : 0);
    }
    orig_os_api.close(fd);
    return ret;
#else
    NOT_IN_USE(if_index);
    return -1;
#endif
}

loops_timer::loops_timer()
{
    m_timeout_msec = -1;
    m_timer_countdown = 0;
    m_interval_it = 2048;
    ts_clear(&m_start);
    ts_clear(&m_elapsed);
    ts_clear(&m_current);
}

void loops_timer::start()
{
    ts_clear(&m_start);
    // set to 1 so the first loop is fast and only after it m_start will be initialized
    m_timer_countdown = 1;
}

int loops_timer::time_left_msec()
{
    if (m_timeout_msec == -1) {
        return -1;
    }

    if (!ts_isset(&m_start)) {
        gettime(&m_start);
    }
    timespec current;
    gettime(&current);
    ts_sub(&current, &m_start, &m_elapsed);

    // cover the case of left<0
    return (m_timeout_msec - ts_to_msec(&m_elapsed)) > 0 ? m_timeout_msec - ts_to_msec(&m_elapsed)
                                                         : 0;
}

///////////////////////////////////////////
uint32_t fd2inode(int fd)
{
    struct stat buf;
    int rc = fstat(fd, &buf);
    return rc == 0 ? buf.st_ino : 0; // no inode is 0
}

///////////////////////////////////////////
xlio_error::xlio_error(const char *_message, const char *_function, const char *_filename,
                       int _lineno, int _errnum) throw()
    : message(_message)
    , function(_function)
    , filename(_filename)
    , lineno(_lineno)
    , errnum(_errnum)
{
    snprintf(formatted_message, sizeof(formatted_message), "xlio_error <%s> (errno=%d %s) in %s:%d",
             message, errnum, strerror(errnum), filename, lineno);
    formatted_message[sizeof(formatted_message) - 1] = '\0';
}

xlio_error::~xlio_error() throw()
{
}

const char *xlio_error::what() const throw()
{
    return formatted_message;
}

///////////////////////////////////////////
