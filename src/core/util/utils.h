/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#ifndef UTILS_H
#define UTILS_H

#include <time.h>
#include <string>
#include <string.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <exception>
#include "vtypes.h"
#include "utils/rdtsc.h"
#include "vlogger/vlogger.h"
#include "core/proto/mem_buf_desc.h"
#include "core/util/xlio_stats.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif /* ARRAY_SIZE */

/**
 * Check if file type is regular
 */
int check_if_regular_file(char *path);

void open_stats_file();

/**
 * L3 and L4 Header Checksum Calculation
 */
void compute_tx_checksum(mem_buf_desc_t *p_mem_buf_desc, bool l3_csum, bool l4_csum);

/**
 * Generic IP Checksum Calculation
 */
unsigned short compute_ip_checksum(const uint16_t *p_data, size_t sz_count);

/**
 * IP Header Checksum Calculation
 */
unsigned short compute_ip_checksum(const iphdr *p_ip_h);

/**
 * IPv6 Dummy Header Checksum method
 */
unsigned short compute_ip_checksum(const ip6_hdr *p_ip_h);

/**
 * get tcp checksum: given IP header and tcp segment (assume checksum field in TCP header contains
 * zero) matches RFC 793
 */
unsigned short compute_tcp_checksum(const struct iphdr *p_iphdr, const uint16_t *p_ip_payload,
                                    uint16_t hdr_len);

unsigned short compute_ipv6_udp_frag_checksum(const ip6_hdr *ipv6, udphdr *udp);

/**
 * Get tcp checksum: given IPv6 header and tcp segment
 */
unsigned short compute_tcp_checksum(const ip6_hdr *p_iphdr, const uint16_t *p_ip_payload,
                                    uint16_t ext_hdr_len);

unsigned short compute_udp_checksum_tx(const ip6_hdr *ipv6, const uint16_t *payload, udphdr *udp);

/**
 * get udp checksum: given IP header and UDP datagram (assume checksum field in UDP header contains
 * zero) matches RFC 793
 */
unsigned short compute_udp_checksum_rx(const struct iphdr *p_iphdr, const struct udphdr *udphdrp,
                                       mem_buf_desc_t *p_rx_wc_buf_desc);

/**
 * get udp checksum: given IPv6 header and UDP datagram (assume checksum field in UDP header
 * contains zero) matches RFC 793
 */
unsigned short compute_udp_checksum_rx(const struct ip6_hdr *p_iphdr, const struct udphdr *udphdrp,
                                       mem_buf_desc_t *p_rx_wc_buf_desc);

/**
 * get user space max number of open fd's using getrlimit, default parameter equals to 1024
 */

int get_sys_max_fd_num(int def_max_fd = 1024);

/**
 * iovec extensions
 * Returns total bytes copyed
 */
int memcpy_fromiovec(u_int8_t *p_dst, const struct iovec *p_iov, size_t sz_iov,
                     size_t sz_src_start_offset, size_t sz_data);

/**
 * get base interface from an aliased/vlan tagged one. i.e. eth2:1 --> eth2 / eth2.1 --> eth2
 * Functions gets:interface name,output variable for base interface,output size; and returns the
 * base interface
 */
int get_base_interface_name(const char *if_name, char *base_ifname, size_t sz_base_ifname);

/**
 * Set the fd blocking mode
 * @param fd the file descriptor on which to operate
 * @param block 'true' to set to block
 *              'false' to set to non-blocking
 */
void set_fd_block_mode(int fd, bool block);

/**
 * @param a number
 * @param b number
 * @return true if 'a' and 'b' are equal. else false.
 */
bool compare_double(double a, double b);

/**
 * Run a system command while bypassing LD_PRELOADed with XLIO
 * @param cmd_line to be exceuted wiout XLIO in process space
 * @param return_str is the output of the system call
 */
int run_and_retreive_system_command(const char *cmd_line, char *return_str, int return_str_len);

const char *iphdr_protocol_type_to_str(const int type);

/**
 * Read content of file detailed in 'path' (usually a sysfs file) and
 * store the file content into the given 'buf' up to 'size' characters.
 * print log in case of failure according to the given 'log_level' argument.
 * @return length of content that was read, or -1 upon any error
 */
int priv_read_file(const char *path, char *buf, size_t size, vlog_levels_t log_level = VLOG_ERROR);

/**
 * like above 'priv_read_file' however make sure that upon success the result in buf is a null
 * terminated string
 */
inline int priv_safe_read_file(const char *path, char *buf, size_t size,
                               vlog_levels_t log_level = VLOG_ERROR)
{
    int ret = -1;
    if (size > 0) {
        ret = priv_read_file(path, buf, size - 1, log_level);
        if (0 <= ret) {
            buf[ret] = '\0';
        }
    }
    return ret;
}

/**
 * like above however make sure that upon success the result in buf is a null terminated string and
 * VLOG_DEBUG
 */
inline int priv_safe_try_read_file(const char *path, char *buf, size_t size)
{
    int ret = -1;
    if (size > 0) {
        ret = priv_read_file(path, buf, size - 1, VLOG_DEBUG);
        if (0 <= ret) {
            buf[ret] = '\0';
        }
    }
    return ret;
}

/**
 * Read content of file detailed in 'path' (usually a sysfs file)
 * upon failure print warning
 * @return int value (atoi) of the file content, or 'default_value' upon failure
 */
int read_file_to_int(const char *path, int default_value, vlog_levels_t log_level = VLOG_WARNING);

/**
 * Get port number from interface name
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @return zero on failure, else port number
 */
int get_port_from_ifname(const char *ifname);

/**
 * Get interface type value from interface name
 *
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @return if type on success or -1 on failure
 */
int get_iftype_from_ifname(const char *ifname);

/**
 * Get interface mtu from interface name
 *
 * @param ifname input interface name of device (e.g. eth1, ib2)
 *  should be of size IFNAMSIZ
 * @return mtu length zero on failure
 */
int get_if_mtu_from_ifname(const char *ifname);

/**
 * Get the OS TCP window scaling factor when tcp_window_scaling is enabled.
 * The value is calculated from the maximum receive buffer value.
 *
 * @param tcp_rmem_max the maximum size of the receive buffer used by each TCP socket
 * @parma core_rmem_max contains the maximum socket receive buffer size in bytes which a user may
 * set by using the SO_RCVBUF socket option.
 *
 * @return TCP window scaling factor
 */
int get_window_scaling_factor(int tcp_rmem_max, int core_rmem_max);

/**
 * Get Ethernet ip address from interface name
 *
 * @param ifname input interface name of device (e.g. eth1, ib2)
 * @param addr output ip_address
 * @param family (e.g. AF_INET, AF_INET6)
 *
 * @return -1 on failure
 */
int get_ip_addr_from_ifname(const char *ifname, ip_addr &addr, sa_family_t family = AF_INET);

/**
 * Get Ethernet ip address from interface index
 *
 * @param ifindex input interface index of device
 * @param addr output ip_address
 * @param family (e.g. AF_INET, AF_INET6)
 *
 * @return -1 on failure
 */
int get_ip_addr_from_ifindex(uint32_t ifindex, ip_addr &addr, sa_family_t family = AF_INET);

/**
 * Get vlan id from interface name
 *
 * @param ifname input interface name of device (e.g. eth2, eth2.5)
 * @return the vlan id or 0 if not a vlan
 */
uint16_t get_vlan_id_from_ifname(const char *ifname);

/**
 * Get vlan base name from interface name
 *
 * @param ifname input interface name of device (e.g. eth2, eth2.5)
 * @param base_ifname output base interface name of device (e.g. eth2)
 * @param sz_base_ifname input the size of base_ifname param
 * @return the vlan base name length or 0 if not a vlan
 */
size_t get_vlan_base_name_from_ifname(const char *ifname, char *base_ifname, size_t sz_base_ifname);

/* Upon success - returns the actual address len in bytes; Upon error - returns zero*/
size_t get_local_ll_addr(const char *ifname, unsigned char *addr, int addr_len, bool is_broadcast);

/* Print warning while RoCE Lag is enabled */
void print_roce_lag_warnings(const char *interface, char *disable_path = nullptr,
                             const char *port1 = nullptr, const char *port2 = nullptr);

/*Print a warning to the user when there was an error registering memory*/
void print_warning_rlimit_memlock(size_t length, int error);

bool check_bond_device_exist(const char *ifname);
bool get_bond_active_slave_name(IN const char *bond_name, OUT char *active_slave_name, IN int sz);
bool get_bond_slave_state(IN const char *slave_name, OUT char *curr_state, IN int sz);
bool get_bond_slaves_name_list(IN const char *bond_name, OUT char *slaves_list, IN int sz);
bool check_bond_roce_lag_exist(OUT char *bond_roce_lag_path, int sz, IN const char *slave_name);
bool check_device_exist(const char *ifname, const char *path);
bool check_device_name_ib_name(const char *ifname, const char *ibname);
bool check_netvsc_device_exist(const char *ifname);
bool get_netvsc_slave(IN const char *ifname, OUT char *slave_name, OUT unsigned int &slave_flags);
bool get_interface_oper_state(IN const char *interface_name, OUT char *slaves_list, IN int sz);

bool validate_user_has_cap_net_raw_privliges();

/**
 * Get TSO support using interface index
 *
 * @param if_index input interface index
 * @return 0/1 or -1 on failure
 */
int validate_tso(int if_index);

/**
 * Get LRO support using interface index
 *
 * @param if_index input interface index
 * @return 0/1 or -1 on failure
 */
int validate_lro(int if_index);

inline std::string to_string_val(const int &k)
{
    return std::to_string(k);
}

static inline int get_procname(int pid, char *proc, size_t size)
{
    char app_full_name[PATH_MAX] = {0};
    char proccess_proc_dir[FILE_NAME_MAX_SIZE] = {0};
    char *app_base_name = nullptr;
    int n = -1;

    if (!proc) {
        return -1;
    }

    n = snprintf(proccess_proc_dir, sizeof(proccess_proc_dir), "/proc/%d/exe", pid);
    if (likely((0 < n) && (n < (int)sizeof(proccess_proc_dir)))) {
        n = readlink(proccess_proc_dir, app_full_name, sizeof(app_full_name) - 1);
        if (n > 0) {
            app_full_name[n] = '\0';
            app_base_name = strrchr(app_full_name, '/');
            if (app_base_name) {
                strncpy(proc, app_base_name + 1, size - 1);
                proc[size - 1] = '\0';
                return 0;
            }
        }
    }

    return -1;
}

// Creates multicast MAC from multicast IP
inline void create_multicast_mac_from_ip(unsigned char *mc_mac, const ip_address &addr,
                                         sa_family_t family)
{
    if (!mc_mac) {
        return;
    }

    if (family == AF_INET) {
        in_addr_t ip = addr.get_in_addr();
        mc_mac[0] = 0x01;
        mc_mac[1] = 0x00;
        mc_mac[2] = 0x5e;
        mc_mac[3] = (uint8_t)((ip >> 8) & 0x7f);
        mc_mac[4] = (uint8_t)((ip >> 16) & 0xff);
        mc_mac[5] = (uint8_t)((ip >> 24) & 0xff);
    } else {
        in6_addr ip = addr.get_in6_addr();
        mc_mac[0] = 0x33;
        mc_mac[1] = 0x33;
        mc_mac[2] = ip.s6_addr[12];
        mc_mac[3] = ip.s6_addr[13];
        mc_mac[4] = ip.s6_addr[14];
        mc_mac[5] = ip.s6_addr[15];
    }
}

// @scope Returns the scope of the address.
// @return The type of the address. @see ip_address
uint16_t ipv6_addr_type_scope(const ip_address &addr, uint8_t &scope);

inline bool ipv6_is_addr_type_preferred(uint16_t type)
{
    return ((type & (IPV6_ADDR_MAPPED | IPV6_ADDR_COMPATv4 | IPV6_ADDR_LOOPBACK)) != 0);
}

static inline void create_mgid_from_ipv4_mc_ip(uint8_t *mgid, uint16_t pkey, uint32_t ip)
{

    //  +--------+----+----+-----------------+---------+-------------------+
    //  |   8    |  4 |  4 |     16 bits     | 16 bits |      80 bits      |
    //  +--------+----+----+-----------------+---------+-------------------+
    //  |11111111|0001|scop|<IPoIB signature>|< P_Key >|      group ID     |
    //  +--------+----+----+-----------------+---------+-------------------+
    //  |11111111|0001|0010|01000000000011011|         |      group ID     |
    //  +--------+----+----+-----------------+---------+-------------------+

    // Fixed for multicast
    mgid[0] = 0xff;
    mgid[1] = 0x12;

    // IPoIB signature: 0x401b for ipv4, 0x601b for ipv6
    mgid[2] = 0x40;
    mgid[3] = 0x1b;

    // P_Key
    mgid[4] = (((unsigned char *)(&pkey))[0]);
    /* cppcheck-suppress objectIndex */
    mgid[5] = (((unsigned char *)(&pkey))[1]);

    // group ID - relevant only for ipv4
    mgid[6] = 0x00;
    mgid[7] = 0x00;
    mgid[8] = 0x00;
    mgid[9] = 0x00;
    mgid[10] = 0x00;
    mgid[11] = 0x00;
    mgid[12] = (uint8_t)((ip)&0x0f);
    mgid[13] = (uint8_t)((ip >> 8) & 0xff);
    mgid[14] = (uint8_t)((ip >> 16) & 0xff);
    mgid[15] = (uint8_t)((ip >> 24) & 0xff);

    vlog_printf(
        VLOG_DEBUG,
        "Translated to mgid: "
        "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
        ((unsigned char *)(mgid))[0], ((unsigned char *)(mgid))[1], ((unsigned char *)(mgid))[2],
        ((unsigned char *)(mgid))[3], ((unsigned char *)(mgid))[4], ((unsigned char *)(mgid))[5],
        ((unsigned char *)(mgid))[6], ((unsigned char *)(mgid))[7], ((unsigned char *)(mgid))[8],
        ((unsigned char *)(mgid))[9], ((unsigned char *)(mgid))[10], ((unsigned char *)(mgid))[11],
        ((unsigned char *)(mgid))[12], ((unsigned char *)(mgid))[13], ((unsigned char *)(mgid))[14],
        ((unsigned char *)(mgid))[15]);
}

/**
 * special design for the rx loop.
 */
class loops_timer {
public:
    loops_timer();
    loops_timer(int timeout_msec);
    void start();
    int time_left_msec();
    void set_timeout_msec(int timeout_msec) { m_timeout_msec = timeout_msec; }
    int get_timeout_msec() { return m_timeout_msec; }
    inline bool is_timeout()
    {
        if (m_timeout_msec == -1) {
            return false;
        }

        if (m_timer_countdown > 0) {
            m_timer_countdown--;
            return false;
        }
        // init counter
        m_timer_countdown = m_interval_it;

        if (!ts_isset(&m_start)) {
            gettime(&m_start);
        }
        // update timer
        gettime(&m_current);
        ts_sub(&m_current, &m_start, &m_elapsed);
        vlog_printf(VLOG_FUNC_ALL, "update loops_timer (elapsed time=%ld sec %ld usec\n",
                    ts_to_sec(&m_elapsed), ts_to_usec(&m_elapsed));

        // test for timeout
        if (m_timeout_msec <= ts_to_msec(&m_elapsed)) {
            return true;
        }

        return false;
    }

private:
    timespec m_start;
    timespec m_elapsed;
    timespec m_current;
    int m_interval_it;
    int m_timer_countdown;
    int m_timeout_msec;
};

// Returns the filesystem's inode number for the given 'fd' using 'fstat' system call that assumes
// 32 bit inodes This should be safe for 'proc' filesytem and for standard filesystems
uint32_t fd2inode(int fd);

/**
 * @class xlio_error
 *
 * base class for xlio exceptions classes.
 * Note: xlio code should NOT catch xlio_error; xlio code should only catch exceptions of derived
 * classes
 */
class xlio_error : public std::exception {
    char formatted_message[512];

public:
    const char *const message;
    const char *const function;
    const char *const filename;
    const int lineno;
    const int errnum;

    /**
     * Create an object that contains const members for all the given arguments, plus a formatted
     * message that will be available thru the 'what()' method of base class.
     *
     * The formatted_message will look like this:
     * 		"xlio_error <create internal epoll> (errno=24 Too many open files) in
     * sock/sockinfo.cpp:61" catcher can print it to log like this: fdcoll_loginfo("recovering from
     * %s", e.what());
     */
    xlio_error(const char *_message, const char *_function, const char *_filename, int _lineno,
               int _errnum) throw();

    virtual ~xlio_error() throw();

    virtual const char *what() const throw();
};

/**
 * @class xlio_exception
 * NOTE: ALL exceptions that can be caught by XLIO should be derived of this class
 */
class xlio_exception : public xlio_error {
public:
    xlio_exception(const char *_message, const char *_function, const char *_filename, int _lineno,
                   int _errnum) throw()
        : xlio_error(_message, _function, _filename, _lineno, _errnum)
    {
    }
};

#define create_xlio_exception_class(clsname, basecls)                                              \
    class clsname : public basecls {                                                               \
    public:                                                                                        \
        clsname(const char *_message, const char *_function, const char *_filename, int _lineno,   \
                int _errnum) throw()                                                               \
            : basecls(_message, _function, _filename, _lineno, _errnum)                            \
        {                                                                                          \
        }                                                                                          \
    }

create_xlio_exception_class(xlio_unsupported_api, xlio_error);

#define throw_xlio_exception(msg)                                                                  \
    throw xlio_exception(msg, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)
// uses for throwing  something that is derived from xlio_error and has similar CTOR; msg will
// automatically be class name
#define xlio_throw_object(_class)                                                                  \
    throw _class(#_class, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)
#define xlio_throw_object_with_msg(_class, _msg)                                                   \
    throw _class(_msg, __PRETTY_FUNCTION__, __FILE__, __LINE__, errno)

/* Rounding up to nearest power of 2 */
static inline uint32_t align32pow2(uint32_t x)
{
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    return x + 1;
}

static inline int ilog_2(uint32_t n)
{
    if (n == 0) {
        return 0;
    }

    uint32_t t = 0;
    while ((1 << t) < (int)n) {
        ++t;
    }

    return (int)t;
}

static inline bool is_ilog2(unsigned int x)
{
    return (1 >= __builtin_popcount(x));
}

inline uint16_t calc_sum_of_payload(const iovec *p_iov, const ssize_t sz_iov)
{
    uint32_t sum = 0;
    bool prev_iov_unaligned = false;

    for (ssize_t i = 0; i < sz_iov; i++) {
        size_t iov_len = p_iov[i].iov_len;
        uint16_t *iov_data = reinterpret_cast<uint16_t *>(p_iov[i].iov_base);

        if (unlikely(!iov_data) || unlikely(iov_len <= 0U)) {
            continue;
        }

        // alignment to 16-bits, since checksum is calculated per each 16-bits
        if (prev_iov_unaligned) {
            sum += ((*iov_data) & htons(0xFF00)) << 8;
            iov_data =
                reinterpret_cast<uint16_t *>(reinterpret_cast<u_int8_t *>(p_iov[i].iov_base) + 1);
            iov_len -= 1;
        }

        while (iov_len > 1) {
            sum += *iov_data++;
            iov_len -= 2;
        }

        if ((prev_iov_unaligned = (iov_len > 0))) {
            sum += ((*iov_data) & htons(0xFF00));
        }
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>(sum);
}

#endif
