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

#include <string.h>
#include <ifaddrs.h>
#include <sys/epoll.h>
#include <linux/if_infiniband.h>
#include <linux/if_ether.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/if_tun.h>
#include <sys/epoll.h>
#include <netlink/route/link/vlan.h>
#include <algorithm>
#include <sstream>

#include "utils/bullseye.h"
#include "util/if.h"
#include "dev/net_device_val.h"
#include "util/vtypes.h"
#include "util/utils.h"
#include "util/valgrind.h"
#include "event/event_handler_manager.h"
#include "proto/L2_address.h"
#include "dev/ib_ctx_handler_collection.h"
#include "dev/ring_tap.h"
#include "dev/ring_simple.h"
#include "dev/ring_slave.h"
#include "dev/ring_bond.h"
#include "sock/sock-redirect.h"
#include "dev/net_device_table_mgr.h"
#include "proto/neighbour_table_mgr.h"

#define MODULE_NAME "ndv"

#define nd_logpanic   __log_panic
#define nd_logerr     __log_err
#define nd_logwarn    __log_warn
#define nd_loginfo    __log_info
#define nd_logdbg     __log_info_dbg
#define nd_logfunc    __log_info_func
#define nd_logfuncall __log_info_funcall

ring_alloc_logic_attr::ring_alloc_logic_attr()
    : m_ring_alloc_logic(RING_LOGIC_PER_INTERFACE)
    , m_use_locks(true)
    , m_user_id_key(0)
{
    init();
}

ring_alloc_logic_attr::ring_alloc_logic_attr(ring_logic_t ring_logic, bool use_locks)
    : m_ring_alloc_logic(ring_logic)
    , m_use_locks(use_locks)
    , m_user_id_key(0)
{
    init();
}

ring_alloc_logic_attr::ring_alloc_logic_attr(const ring_alloc_logic_attr &other)
    : m_hash(other.m_hash)
    , m_ring_alloc_logic(other.m_ring_alloc_logic)
    , m_use_locks(other.m_use_locks)
    , m_user_id_key(other.m_user_id_key)
{
}

void ring_alloc_logic_attr::init()
{
    size_t h = 5381;

#define HASH_ITER(val, type)                                                                       \
    do {                                                                                           \
        type x = (type)val;                                                                        \
        do {                                                                                       \
            /* m_hash * 33 + byte */                                                               \
            h = (h << 5) + h + (x & 0xff);                                                         \
            x >>= 8;                                                                               \
        } while (x != 0);                                                                          \
    } while (0)

#undef HASH_ITER
#define HASH_ITER(val, type) h = h * 19 + (size_t)val;

    HASH_ITER(m_ring_alloc_logic, size_t);
    HASH_ITER(m_user_id_key, uint64_t);
    HASH_ITER(m_use_locks, bool);

    m_hash = h;
#undef HASH_ITER
}

void ring_alloc_logic_attr::set_ring_alloc_logic(ring_logic_t logic)
{
    if (m_ring_alloc_logic != logic) {
        m_ring_alloc_logic = logic;
        init();
    }
}

void ring_alloc_logic_attr::set_user_id_key(uint64_t user_id_key)
{
    if (m_user_id_key != user_id_key) {
        m_user_id_key = user_id_key;
        init();
    }
}

void ring_alloc_logic_attr::set_use_locks(bool use_locks)
{
    if (m_use_locks != use_locks) {
        m_use_locks = use_locks;
        init();
    }
}

const std::string ring_alloc_logic_attr::to_str() const
{
    std::stringstream ss;

    ss << "allocation logic " << m_ring_alloc_logic << " key " << m_user_id_key << " use locks "
       << !!m_use_locks;

    return ss.str();
}

net_device_val::net_device_val(struct net_device_val_desc *desc)
    : m_lock(MULTILOCK_RECURSIVE, "net_device_val")
{
    bool valid = false;
    ib_ctx_handler *ib_ctx;
    struct nlmsghdr *nl_msg = nullptr;
    struct ifinfomsg *nl_msgdata = nullptr;
    int nl_attrlen;
    struct rtattr *nl_attr;

    m_if_idx = 0;
    m_if_link = 0;
    m_type = 0;
    m_flags = 0;
    m_mtu = 0;
    m_state = INVALID;
    m_p_L2_addr = nullptr;
    m_p_br_addr = nullptr;
    m_bond = NO_BOND;
    m_if_active = 0;
    m_bond_xmit_hash_policy = XHP_LAYER_2;
    m_bond_fail_over_mac = 0;
    m_transport_type = XLIO_TRANSPORT_UNKNOWN;

    if (!desc) {
        nd_logerr("Invalid net_device_val name=%s", "NA");
        m_state = INVALID;
        return;
    }

    nl_msg = desc->nl_msg;
    nl_msgdata = (struct ifinfomsg *)NLMSG_DATA(nl_msg);

    nl_attr = (struct rtattr *)IFLA_RTA(nl_msgdata);
    nl_attrlen = IFLA_PAYLOAD(nl_msg);

    set_type(nl_msgdata->ifi_type);
    set_if_idx(nl_msgdata->ifi_index);
    set_flags(nl_msgdata->ifi_flags);
    while (RTA_OK(nl_attr, nl_attrlen)) {
        char *nl_attrdata = (char *)RTA_DATA(nl_attr);
        size_t nl_attrpayload = RTA_PAYLOAD(nl_attr);

        switch (nl_attr->rta_type) {
        case IFLA_MTU:
            set_mtu(*(int32_t *)nl_attrdata);
            break;
        case IFLA_LINK:
            set_if_link(*(int32_t *)nl_attrdata);
            break;
        case IFLA_IFNAME:
            set_ifname(nl_attrdata);
            break;
        case IFLA_ADDRESS:
            set_l2_if_addr((uint8_t *)nl_attrdata, nl_attrpayload);
            break;
        case IFLA_BROADCAST:
            set_l2_bc_addr((uint8_t *)nl_attrdata, nl_attrpayload);
            break;
        default:
            break;
        }
        nl_attr = RTA_NEXT(nl_attr, nl_attrlen);
    }

    /* Valid interface should have at least one IP address */
    set_ip_array();
    if (m_ipv4.empty() && m_ipv6.empty()) {
        return;
    }

    /* Identify device type */
    if ((get_flags() & IFF_MASTER) || check_bond_device_exist(get_ifname_link())) {
        verify_bonding_mode();
    } else if (check_netvsc_device_exist(get_ifname_link())) {
        m_bond = NETVSC;
    } else {
        m_bond = NO_BOND;
    }

    nd_logdbg("Check interface '%s' (index=%d flags=%X)", get_ifname(), get_if_idx(), get_flags());

    valid = false;
    ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(get_ifname_link());
    switch (m_bond) {
    case NETVSC:
        if (get_type() == ARPHRD_ETHER) {
            char slave_ifname[IFNAMSIZ] = {0};
            unsigned int slave_flags = 0;
            /* valid = true; uncomment it is valid flow to operate w/o SRIOV */
            if (get_netvsc_slave(get_ifname_link(), slave_ifname, slave_flags)) {
                valid = verify_qp_creation(slave_ifname, IBV_QPT_RAW_PACKET);
            }
        }
        break;
    case LAG_8023ad:
    case ACTIVE_BACKUP:
        // this is a bond interface (or a vlan/alias over bond), find the slaves
        valid = verify_bond_or_eth_qp_creation();
        break;
    default:
        valid = (bool)(ib_ctx && verify_eth_qp_creation(get_ifname_link()));
        break;
    }

    if (!valid) {
        nd_logdbg("Skip interface '%s'", get_ifname());
        return;
    }

    if (safe_mce_sys().mtu != 0 && (int)safe_mce_sys().mtu != get_mtu()) {
        nd_logwarn("Mismatch between interface %s MTU=%d and XLIO_MTU=%d."
                   "Make sure XLIO_MTU and all offloaded interfaces MTUs match.",
                   get_ifname(), get_mtu(), safe_mce_sys().mtu);
    }

    m_ipv6_optimistic_dad =
        (sysctl_reader_t::instance().get_ipv6_if_optimistic_dad(get_ifname()) != 0);
    m_ipv6_use_optimistic =
        (sysctl_reader_t::instance().get_ipv6_if_use_optimistic(get_ifname()) != 0);
    m_ipv6_use_tempaddr = sysctl_reader_t::instance().get_ipv6_if_use_tempaddr(get_ifname());

    /* Set interface state after all verifications */
    if (m_flags & IFF_RUNNING) {
        m_state = RUNNING;
    } else {
        if (m_flags & IFF_UP) {
            m_state = UP;
        } else {
            m_state = DOWN;
        }
    }

    nd_logdbg("Use interface '%s'", get_ifname());
    if (ib_ctx) {
        nd_logdbg("%s ==> %s port %d (%s)", get_ifname(), ib_ctx->get_ibname().c_str(),
                  get_port_from_ifname(get_ifname_link()),
                  (ib_ctx->is_active(get_port_from_ifname(get_ifname_link())) ? "Up" : "Down"));
    } else {
        nd_logdbg("%s ==> none", get_ifname());
    }
}

net_device_val::~net_device_val()
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    rings_hash_map_t::iterator ring_iter;
    while ((ring_iter = m_h_ring_map.begin()) != m_h_ring_map.end()) {
        delete THE_RING;
        resource_allocation_key *tmp = ring_iter->first;
        m_h_ring_map.erase(ring_iter);
        delete tmp;
    }

    rings_key_redirection_hash_map_t::iterator redirect_iter;
    while ((redirect_iter = m_h_ring_key_redirection_map.begin()) !=
           m_h_ring_key_redirection_map.end()) {
        delete redirect_iter->second.first;
        m_h_ring_key_redirection_map.erase(redirect_iter);
    }
    if (m_p_br_addr) {
        delete m_p_br_addr;
        m_p_br_addr = nullptr;
    }

    if (m_p_L2_addr) {
        delete m_p_L2_addr;
        m_p_L2_addr = nullptr;
    }

    slave_data_vector_t::iterator slave = m_slaves.begin();
    for (; slave != m_slaves.end(); ++slave) {
        delete *slave;
    }
}

void net_device_val::set_ip_array()
{
    int rc = 0;
    int fd = -1;
    struct {
        struct nlmsghdr hdr;
        struct ifaddrmsg addrmsg;
    } nl_req;
    struct nlmsghdr *nl_msg;
    int nl_msglen = 0;
    char nl_res[8096];
    static int _seq = 0;

    /* Set up the netlink socket */
    fd = SYSCALL(socket, AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        nd_logerr("netlink socket() creation");
        return;
    }

    /* Prepare RTM_GETADDR request */
    memset(&nl_req, 0, sizeof(nl_req));
    nl_req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nl_req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nl_req.hdr.nlmsg_type = RTM_GETADDR;
    nl_req.hdr.nlmsg_seq = _seq++;
    nl_req.hdr.nlmsg_pid = getpid();
    nl_req.addrmsg.ifa_family = AF_UNSPEC;
    nl_req.addrmsg.ifa_index = m_if_idx;

    /* Send the netlink request */
    rc = SYSCALL(send, fd, &nl_req, nl_req.hdr.nlmsg_len, 0);
    if (rc < 0) {
        nd_logerr("netlink send() operation");
        goto ret;
    }

    do {
        /* Receive the netlink reply */
        rc = SYSCALL(recv, fd, nl_res, sizeof(nl_res), 0);
        if (rc < 0) {
            nd_logerr("netlink recv() operation");
            goto ret;
        }

        nl_msg = (struct nlmsghdr *)nl_res;
        nl_msglen = rc;
        while (NLMSG_OK(nl_msg, (size_t)nl_msglen) && (nl_msg->nlmsg_type != NLMSG_ERROR)) {
            int nl_attrlen;
            struct ifaddrmsg *nl_msgdata;
            struct rtattr *nl_attr;

            nl_msgdata = (struct ifaddrmsg *)NLMSG_DATA(nl_msg);

            /* Process just specific if index */
            if ((int)nl_msgdata->ifa_index == m_if_idx &&
                (nl_msgdata->ifa_family == AF_INET || nl_msgdata->ifa_family == AF_INET6)) {
                nl_attr = (struct rtattr *)IFA_RTA(nl_msgdata);
                nl_attrlen = IFA_PAYLOAD(nl_msg);

                std::unique_ptr<ip_data> p_val(new ip_data);
                p_val->flags = nl_msgdata->ifa_flags;
                p_val->prefixlen = nl_msgdata->ifa_prefixlen;
                p_val->scope = nl_msgdata->ifa_scope;
                while (RTA_OK(nl_attr, nl_attrlen)) {
                    char *nl_attrdata = reinterpret_cast<char *>(RTA_DATA(nl_attr));

                    if (nl_attr->rta_type == IFA_ADDRESS) {
                        if (nl_msgdata->ifa_family == AF_INET) {
                            p_val->local_addr =
                                ip_address(*reinterpret_cast<in_addr *>(nl_attrdata));
                        } else {
                            p_val->local_addr =
                                ip_address(*reinterpret_cast<in6_addr *>(nl_attrdata));
                        }
                        break;
                    }
                    nl_attr = RTA_NEXT(nl_attr, nl_attrlen);
                }

                if (nl_msgdata->ifa_family == AF_INET) {
                    m_ipv4.emplace_back(std::move(p_val));
                } else {
                    m_ipv6.emplace_back(std::move(p_val));
                }
            }

            /* Check if it is the last message */
            if (nl_msg->nlmsg_type == NLMSG_DONE) {
                goto ret;
            }
            nl_msg = NLMSG_NEXT(nl_msg, nl_msglen);
        }
    } while (1);

ret:
    SYSCALL(close, fd);

    print_ips();
}

void net_device_val::print_ips()
{
    if (g_vlogger_level < VLOG_DEBUG) {
        return;
    }

    auto print_arr = [this](const ip_data_vector_t &vec, sa_family_t family) {
        if (vec.empty()) {
            return;
        }

        VLOG_PRINTF_INFO(VLOG_DEBUG, "IF %s %s:", get_ifname(), sa_family2str(family).c_str());

        for (const auto &ipdata : vec) {
            VLOG_PRINTF_INFO(VLOG_DEBUG, "\t%s/%" PRIu8 " scope: %" PRIu8 " flags: %d",
                             ipdata->local_addr.to_str(family).c_str(), ipdata->prefixlen,
                             ipdata->scope, ipdata->flags);
        }
    };

    print_arr(m_ipv4, AF_INET);
    print_arr(m_ipv6, AF_INET6);
}

const std::string net_device_val::to_str_ex() const
{
    std::string rc;

    static const struct {
        int flag;
        const char *name;
    } s_flags_tbl[] = {
        {IFF_UP, "UP"},
        {IFF_RUNNING, "RUNNING"},
        {IFF_NOARP, "NO_ARP"},
        {IFF_LOOPBACK, "LOOPBACK"},
        {IFF_BROADCAST, "BROADCAST"},
        {IFF_MULTICAST, "MULTICAST"},
        {IFF_MASTER, "MASTER"},
        {IFF_SLAVE, "SLAVE"},
        {IFF_LOWER_UP, "LOWER_UP"},
        {IFF_DEBUG, "DEBUG"},
        {IFF_PROMISC, "PROMISC"},
    };

    rc = std::to_string(m_if_idx) + ": ";
    rc += get_ifname();
    if (strcmp(get_ifname(), get_ifname_link()) != 0) {
        rc += "@";
        rc += get_ifname_link();
    }

    rc += " <";
    int flags = m_flags;
    for (size_t i = 0; flags && i < ARRAY_SIZE(s_flags_tbl); ++i) {
        if (flags & s_flags_tbl[i].flag) {
            rc += s_flags_tbl[i].name;
            flags &= ~s_flags_tbl[i].flag;
            if (flags != 0) {
                rc += ",";
            }
        }
    }
    if (flags != 0) {
        rc += "UNKNOWN_FLAG";
    }
    rc += ">:";

    rc += " mtu " + std::to_string(m_mtu);

    rc += " type ";
    switch (m_type) {
    case ARPHRD_LOOPBACK:
        rc += "loopback";
        break;
    case ARPHRD_ETHER:
        rc += "ether";
        break;
    default:
        rc += "unknown";
        break;
    }

    rc += " (";
    switch (m_bond) {
    case NETVSC:
        rc += "netvsc";
        break;
    case LAG_8023ad:
        rc += "lag 8023ad";
        break;
    case ACTIVE_BACKUP:
        rc += "active backup";
        break;
    default:
        rc += "normal";
        break;
    }
    rc += ")";

    return rc;
}

void net_device_val::print_val() const
{
#if (MAX_DEFINED_LOG_LEVEL >= DEFINED_VLOG_DEBUG)
    nd_logdbg("%s", to_str_ex().c_str());

    nd_logdbg("  IPv4 list: %s", (m_ipv4.empty() ? "empty " : ""));
    std::for_each(m_ipv4.begin(), m_ipv4.end(), [this](const std::unique_ptr<ip_data> &ip) {
        nd_logdbg("    inet: %s/%d flags: 0x%X scope: 0x%x", ip->local_addr.to_str(AF_INET).c_str(),
                  ip->prefixlen, ip->flags, ip->scope);
    });

    nd_logdbg("  IPv6 list: %s", (m_ipv6.empty() ? "empty " : ""));
    std::for_each(m_ipv6.begin(), m_ipv6.end(), [this](const std::unique_ptr<ip_data> &ip) {
        nd_logdbg("    inet6: %s/%d flags: 0x%X scope: 0x%x",
                  ip->local_addr.to_str(AF_INET6).c_str(), ip->prefixlen, ip->flags, ip->scope);
    });

    nd_logdbg("  slave list: %s", (m_slaves.empty() ? "empty " : ""));
    for (size_t i = 0; i < m_slaves.size(); i++) {
        char if_name[IFNAMSIZ] = {0};

        if_name[0] = '\0';
        if_indextoname(m_slaves[i]->if_index, if_name);
        nd_logdbg("    %d: %s: %s active: %d ib: %s", m_slaves[i]->if_index, if_name,
                  m_slaves[i]->p_L2_addr->to_str().c_str(), m_slaves[i]->active,
                  (m_slaves[i]->p_ib_ctx ? m_slaves[i]->p_ib_ctx->get_ibname().c_str() : "n/a"));
    }

    nd_logdbg("  ring list: %s", (m_h_ring_map.empty() ? "empty " : ""));
    for (auto ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ++ring_iter) {
        ring *cur_ring = ring_iter->second.first;
        nd_logdbg("    %d: %p: parent %p ref %d", cur_ring->get_if_index(), cur_ring,
                  cur_ring->get_parent(), ring_iter->second.second);
    }
#endif /* MAX_DEFINED_LOG_LEVEL */
}

void net_device_val::set_slave_array()
{
    char active_slave[IFNAMSIZ] = {0}; // gather the slave data (only for active-backup)-

    nd_logdbg("");

    if (m_bond == NETVSC) {
        slave_data_t *s = nullptr;
        unsigned int slave_flags = 0;
        if (get_netvsc_slave(get_ifname_link(), active_slave, slave_flags)) {
            if ((slave_flags & IFF_UP) && verify_qp_creation(active_slave, IBV_QPT_RAW_PACKET)) {
                s = new slave_data_t(if_nametoindex(active_slave));
                m_slaves.push_back(s);
            }
        }
    } else if (m_bond == NO_BOND) {
        slave_data_t *s = new slave_data_t(if_nametoindex(get_ifname()));
        m_slaves.push_back(s);
    } else {
        // bond device

        // get list of all slave devices
        char slaves_list[IFNAMSIZ * MAX_SLAVES] = {0};
        if (get_bond_slaves_name_list(get_ifname_link(), slaves_list, sizeof(slaves_list))) {
            char *slave = strtok(slaves_list, " ");
            while (slave) {
                char *p = strchr(slave, '\n');
                if (p) {
                    *p = '\0'; // Remove the tailing 'new line" char
                }

                slave_data_t *s = new slave_data_t(if_nametoindex(slave));
                m_slaves.push_back(s);
                slave = strtok(nullptr, " ");
            }
        }

        // find the active slave
        if (get_bond_active_slave_name(get_ifname_link(), active_slave, sizeof(active_slave))) {
            m_if_active = if_nametoindex(active_slave);
            nd_logdbg("found the active slave: %d: '%s'", m_if_active, active_slave);
        } else {
            nd_logdbg("failed to find the active slave, Moving to LAG state");
        }
    }

    bool up_and_active_slaves[m_slaves.size()];

    memset(up_and_active_slaves, 0, sizeof(up_and_active_slaves));

    if (m_bond == LAG_8023ad) {
        get_up_and_active_slaves(up_and_active_slaves, m_slaves.size());
    }

    for (uint16_t i = 0; i < m_slaves.size(); i++) {
        char if_name[IFNAMSIZ] = {0};
        char base_ifname[IFNAMSIZ];

        if (!if_indextoname(m_slaves[i]->if_index, if_name)) {
            nd_logerr("Can not find interface name by index=%d", m_slaves[i]->if_index);
            continue;
        }
        get_base_interface_name((const char *)if_name, base_ifname, sizeof(base_ifname));

        // Save L2 address
        m_slaves[i]->p_L2_addr = create_L2_address(if_name);
        m_slaves[i]->active = false;

        if (m_bond == ACTIVE_BACKUP && m_if_active == m_slaves[i]->if_index) {
            m_slaves[i]->active = true;
        }

        if (m_bond == LAG_8023ad) {
            if (up_and_active_slaves[i]) {
                m_slaves[i]->active = true;
            }
        }

        if (m_bond == NETVSC) {
            m_slaves[i]->active = true;
        }

        if (m_bond == NO_BOND) {
            m_slaves[i]->active = true;
        }

        m_slaves[i]->p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(base_ifname);
        if (!m_slaves[i]->p_ib_ctx) {
            continue;
        }

        m_slaves[i]->port_num = get_port_from_ifname(base_ifname);
        if (m_slaves[i]->port_num < 1) {
            nd_logdbg("Error: incorrect port: %d for ifname=%s base_ifname=%s",
                      m_slaves[i]->port_num, if_name, base_ifname);
        }

        /* Initialization for RoCE LAG device */
        if (m_bond != NO_BOND && strstr(m_slaves[i]->p_ib_ctx->get_ibname().c_str(), "bond")) {
            m_slaves[i]->port_num = get_port_from_ifname(get_ifname_link());
            m_slaves[i]->lag_tx_port_affinity = i + 1;
        }
    }

    if (m_slaves.empty() && NETVSC != m_bond) {
        m_state = INVALID;
        nd_logpanic("No slave found.");
    }
}

const slave_data_t *net_device_val::get_slave(int if_index)
{
    std::lock_guard<decltype(m_lock)> lock(m_lock);

    slave_data_vector_t::iterator iter;
    for (iter = m_slaves.begin(); iter != m_slaves.end(); iter++) {
        slave_data_t *cur_slave = *iter;
        if (cur_slave->if_index == if_index) {
            return cur_slave;
        }
    }
    return nullptr;
}

void net_device_val::verify_bonding_mode()
{
    // this is a bond interface, lets get its mode.
    char bond_mode_file_content[FILENAME_MAX];
    char bond_failover_mac_file_content[FILENAME_MAX];
    char bond_mode_param_file[FILENAME_MAX];
    char bond_failover_mac_param_file[FILENAME_MAX];
    char bond_xmit_hash_policy_file_content[FILENAME_MAX];
    char bond_xmit_hash_policy_param_file[FILENAME_MAX];

    memset(bond_mode_file_content, 0, FILENAME_MAX);
    sprintf(bond_mode_param_file, BONDING_MODE_PARAM_FILE, get_ifname_link());
    sprintf(bond_failover_mac_param_file, BONDING_FAILOVER_MAC_PARAM_FILE, get_ifname_link());

    if (priv_safe_read_file(bond_mode_param_file, bond_mode_file_content, FILENAME_MAX) > 0) {
        char *bond_mode = nullptr;
        bond_mode = strtok(bond_mode_file_content, " ");
        if (bond_mode) {
            if (!strcmp(bond_mode, "active-backup")) {
                m_bond = ACTIVE_BACKUP;
            } else if (strstr(bond_mode, "802.3ad")) {
                m_bond = LAG_8023ad;
            }
            if (priv_safe_read_file(bond_failover_mac_param_file, bond_failover_mac_file_content,
                                    FILENAME_MAX) > 0) {
                if (strstr(bond_failover_mac_file_content, "0")) {
                    m_bond_fail_over_mac = 0;
                } else if (strstr(bond_failover_mac_file_content, "1")) {
                    m_bond_fail_over_mac = 1;
                } else if (strstr(bond_failover_mac_file_content, "2")) {
                    m_bond_fail_over_mac = 2;
                }
            }
        }
    }

    memset(bond_xmit_hash_policy_file_content, 0, FILENAME_MAX);
    sprintf(bond_xmit_hash_policy_param_file, BONDING_XMIT_HASH_POLICY_PARAM_FILE,
            get_ifname_link());
    if (priv_safe_try_read_file(bond_xmit_hash_policy_param_file,
                                bond_xmit_hash_policy_file_content, FILENAME_MAX) > 0) {
        char *bond_xhp = nullptr;
        char *saveptr = nullptr;

        bond_xhp = strtok_r(bond_xmit_hash_policy_file_content, " ", &saveptr);
        if (!bond_xhp) {
            nd_logdbg("could not parse bond xmit hash policy, staying with default (L2)\n");
        } else {
            bond_xhp = strtok_r(nullptr, " ", &saveptr);
            if (bond_xhp) {
                m_bond_xmit_hash_policy = (bond_xmit_hash_policy)strtol(bond_xhp, nullptr, 10);
                if (m_bond_xmit_hash_policy < XHP_LAYER_2 ||
                    m_bond_xmit_hash_policy > XHP_ENCAP_3_4) {
                    vlog_printf(VLOG_WARNING,
                                "" PRODUCT_NAME " does not support xmit hash policy = %d\n",
                                m_bond_xmit_hash_policy);
                    m_bond_xmit_hash_policy = XHP_LAYER_2;
                }
            }
            nd_logdbg("got bond xmit hash policy = %d\n", m_bond_xmit_hash_policy);
        }
    } else {
        nd_logdbg("could not read bond xmit hash policy, staying with default (L2)\n");
    }

    if (m_bond == NO_BOND || m_bond_fail_over_mac > 1) {
        vlog_printf(
            VLOG_WARNING,
            "******************************************************************************\n");
        vlog_printf(VLOG_WARNING,
                    "" PRODUCT_NAME " doesn't support current bonding configuration of %s.\n",
                    get_ifname_link());
        vlog_printf(
            VLOG_WARNING,
            "The only supported bonding mode is \"802.3ad 4(#4)\" or \"active-backup(#1)\"\n");
        vlog_printf(VLOG_WARNING, "with \"fail_over_mac=1\" or \"fail_over_mac=0\".\n");
        vlog_printf(VLOG_WARNING,
                    "The effect of working in unsupported bonding mode is undefined.\n");
        vlog_printf(VLOG_WARNING,
                    "Read more about Bonding in the " PRODUCT_NAME "'s User Manual\n");
        vlog_printf(
            VLOG_WARNING,
            "******************************************************************************\n");
    }
}

/**
 * only for active-backup bond
 */
bool net_device_val::update_active_backup_slaves()
{
    // update the active slave
    // /sys/class/net/bond0/bonding/active_slave
    char active_slave[IFNAMSIZ * MAX_SLAVES] = {0};
    int if_active_slave = 0;

    if (!get_bond_active_slave_name(get_ifname_link(), active_slave, IFNAMSIZ)) {
        nd_logdbg("failed to find the active slave!");
        return 0;
    }

    // nothing changed
    if_active_slave = if_nametoindex(active_slave);
    if (m_if_active == if_active_slave) {
        return 0;
    }

    m_p_L2_addr = create_L2_address(get_ifname());
    bool found_active_slave = false;
    for (size_t i = 0; i < m_slaves.size(); i++) {
        if (if_active_slave == m_slaves[i]->if_index) {
            m_slaves[i]->active = true;
            found_active_slave = true;
            nd_logdbg("Slave changed old=%d new=%d", m_if_active, if_active_slave);
            m_if_active = if_active_slave;
        } else {
            m_slaves[i]->active = false;
        }
    }
    if (!found_active_slave) {
        nd_logdbg("Failed to locate new active slave details");
        return 0;
    }
    // restart rings
    rings_hash_map_t::iterator ring_iter;
    for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
        THE_RING->restart();
    }
    return 1;
}

/*
 * this function assume m_slaves[i]->if_name and m_slaves.size() are already set.
 */
bool net_device_val::get_up_and_active_slaves(bool *up_and_active_slaves, size_t size)
{
    bool up_slaves[m_slaves.size()];
    int num_up = 0;
    bool active_slaves[m_slaves.size()];
    int num_up_and_active = 0;
    size_t i = 0;

    if (size != m_slaves.size()) {
        nd_logwarn("programmer error! array size is not correct");
        return false;
    }

    /* get slaves operstate and active state */
    for (i = 0; i < m_slaves.size(); i++) {
        char oper_state[5] = {0};
        char slave_state[10] = {0};
        char if_name[IFNAMSIZ] = {0};

        up_slaves[i] = false;
        if (!if_indextoname(m_slaves[i]->if_index, if_name)) {
            nd_logerr("Can not find interface name by index=%d", m_slaves[i]->if_index);
            continue;
        }

        // get interface operstate
        get_interface_oper_state(if_name, oper_state, sizeof(oper_state));
        if (strstr(oper_state, "up")) {
            num_up++;
            up_slaves[i] = true;
        }

        active_slaves[i] = true;
        // get slave state
        if (get_bond_slave_state(if_name, slave_state, sizeof(slave_state))) {
            if (!strstr(slave_state, "active")) {
                active_slaves[i] = false;
            }
        }

        if (active_slaves[i] && up_slaves[i]) {
            up_and_active_slaves[i] = true;
            num_up_and_active++;
        } else {
            up_and_active_slaves[i] = false;
        }
    }

    /* make sure at least one up interface is active */
    if (!num_up_and_active && num_up) {
        for (i = 0; i < m_slaves.size(); i++) {
            if (up_slaves[i]) {
                up_and_active_slaves[i] = true;
                break;
            }
        }
    }

    return true;
}

bool net_device_val::update_active_slaves()
{
    bool changed = false;
    bool up_and_active_slaves[m_slaves.size()];
    size_t i = 0;

    memset(&up_and_active_slaves, 0, m_slaves.size() * sizeof(bool));
    get_up_and_active_slaves(up_and_active_slaves, m_slaves.size());

    /* compare to current status and prepare for restart */
    for (i = 0; i < m_slaves.size(); i++) {
        if (up_and_active_slaves[i]) {
            // slave came up
            if (!m_slaves[i]->active) {
                nd_logdbg("slave %d is up ", m_slaves[i]->if_index);
                m_slaves[i]->active = true;
                changed = true;
            }
        } else {
            // slave went down
            if (m_slaves[i]->active) {
                nd_logdbg("slave %d is down ", m_slaves[i]->if_index);
                m_slaves[i]->active = false;
                changed = true;
            }
        }
    }

    /* restart if status changed */
    if (changed) {
        m_p_L2_addr = create_L2_address(get_ifname());
        // restart rings
        rings_hash_map_t::iterator ring_iter;
        for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
            THE_RING->restart();
        }
        return 1;
    }
    return 0;
}

void net_device_val::update_netvsc_slaves(int if_index, int if_flags)
{
    slave_data_t *s = nullptr;
    bool found = false;
    ib_ctx_handler *ib_ctx = nullptr, *up_ib_ctx = nullptr;
    char if_name[IFNAMSIZ] = {0};

    m_lock.lock();

    if (if_indextoname(if_index, if_name) && (if_flags & IFF_UP) && (if_flags & IFF_RUNNING)) {
        nd_logdbg("slave %d is up", if_index);

        g_p_ib_ctx_handler_collection->update_tbl(if_name);
        if ((up_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(if_name))) {
            s = new slave_data_t(if_index);
            s->active = true;
            s->p_ib_ctx = up_ib_ctx;
            s->p_L2_addr = create_L2_address(if_name);
            s->port_num = get_port_from_ifname(if_name);
            m_slaves.push_back(s);

            up_ib_ctx->set_ctx_time_converter_status(
                g_p_net_device_table_mgr->get_ctx_time_conversion_mode());
            g_buffer_pool_rx_rwqe->register_memory(s->p_ib_ctx);
            g_buffer_pool_tx->register_memory(s->p_ib_ctx);
            found = true;
        }
    } else {
        if (!m_slaves.empty()) {
            s = m_slaves.back();
            m_slaves.pop_back();

            nd_logdbg("slave %d is down ", s->if_index);

            ib_ctx = s->p_ib_ctx;
            delete s;
            found = true;
        }
    }

    m_lock.unlock();

    if (!found) {
        nd_logdbg("Unable to detect any changes for interface %d. ignoring", if_index);
        return;
    }

    /* restart if status changed */
    m_p_L2_addr = create_L2_address(get_ifname());
    // restart rings
    rings_hash_map_t::iterator ring_iter;
    for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
        THE_RING->restart();
    }

    if (ib_ctx) {
        g_p_ib_ctx_handler_collection->del_ib_ctx(ib_ctx);
    }
}

const std::string net_device_val::to_str() const
{
    return std::string("Net Device: " + m_name);
}

ring *net_device_val::reserve_ring(resource_allocation_key *key)
{
    nd_logfunc("");
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    key = ring_key_redirection_reserve(key);
    ring *the_ring = nullptr;
    rings_hash_map_t::iterator ring_iter = m_h_ring_map.find(key);

    if (m_h_ring_map.end() == ring_iter) {
        nd_logdbg("Creating new RING for %s", key->to_str().c_str());
        // Copy key since we keep pointer and socket can die so map will lose pointer
        resource_allocation_key *new_key = new resource_allocation_key(*key);
        the_ring = create_ring(new_key);
        if (!the_ring) {
            return nullptr;
        }
        m_h_ring_map[new_key] = std::make_pair(the_ring, 0); // each ring is born with ref_count = 0
        ring_iter = m_h_ring_map.find(new_key);
        epoll_event ev = {0, {nullptr}};
        size_t num_ring_rx_fds;
        int *ring_rx_fds_array = the_ring->get_rx_channel_fds(num_ring_rx_fds);
        ev.events = EPOLLIN;
        for (size_t i = 0; i < num_ring_rx_fds; i++) {
            int cq_ch_fd = ring_rx_fds_array[i];
            ev.data.fd = cq_ch_fd;
            BULLSEYE_EXCLUDE_BLOCK_START
            if (unlikely(SYSCALL(epoll_ctl, g_p_net_device_table_mgr->global_ring_epfd_get(),
                                 EPOLL_CTL_ADD, cq_ch_fd, &ev))) {
                nd_logerr(
                    "Failed to add RING notification fd to global_table_mgr_epfd (errno=%d %s)",
                    errno, strerror(errno));
            }
            BULLSEYE_EXCLUDE_BLOCK_END
        }

        if (key->get_ring_alloc_logic() == RING_LOGIC_ISOLATE) {
            // Keep isolated rings until termination. Destructor will delete the ring.
            ADD_RING_REF_CNT;
        }
        g_p_net_device_table_mgr->global_ring_wakeup();
    }

    ADD_RING_REF_CNT;
    the_ring = GET_THE_RING(key);

    nd_logdbg("%p: if_index %d parent %p ref %d key %s", the_ring, the_ring->get_if_index(),
              the_ring->get_parent(), RING_REF_CNT, key->to_str().c_str());

    return the_ring;
}

int net_device_val::release_ring(resource_allocation_key *key)
{
    nd_logfunc("");

    resource_allocation_key *red_key;

    std::lock_guard<decltype(m_lock)> lock(m_lock);
    red_key = get_ring_key_redirection(key);
    ring *the_ring = nullptr;
    rings_hash_map_t::iterator ring_iter = m_h_ring_map.find(red_key);

    if (m_h_ring_map.end() != ring_iter) {
        DEC_RING_REF_CNT;
        the_ring = GET_THE_RING(red_key);

        nd_logdbg("%p: if_index %d parent %p ref %d key %s", the_ring, the_ring->get_if_index(),
                  the_ring->get_parent(), RING_REF_CNT, red_key->to_str().c_str());

        if (TEST_REF_CNT_ZERO) {
            size_t num_ring_rx_fds;
            int *ring_rx_fds_array = the_ring->get_rx_channel_fds(num_ring_rx_fds);
            nd_logdbg("Deleting RING %p for key %s and removing notification fd from "
                      "global_table_mgr_epfd (epfd=%d)",
                      the_ring, red_key->to_str().c_str(),
                      g_p_net_device_table_mgr->global_ring_epfd_get());
            for (size_t i = 0; i < num_ring_rx_fds; i++) {
                int cq_ch_fd = ring_rx_fds_array[i];
                BULLSEYE_EXCLUDE_BLOCK_START
                if (unlikely((SYSCALL(epoll_ctl, g_p_net_device_table_mgr->global_ring_epfd_get(),
                                      EPOLL_CTL_DEL, cq_ch_fd, nullptr)) &&
                             (!(errno == ENOENT || errno == EBADF)))) {
                    nd_logerr("Failed to delete RING notification fd to global_table_mgr_epfd "
                              "(errno=%d %s)",
                              errno, strerror(errno));
                }
                BULLSEYE_EXCLUDE_BLOCK_END
            }

            ring_key_redirection_release(key);

            delete the_ring;
            delete ring_iter->first;
            m_h_ring_map.erase(ring_iter);

            return 0;
        }
        return RING_REF_CNT;
    }
    return (-1);
}

/*
 * this function maps key to new keys that it created
 * the key that it creates is the size of the map
 */
resource_allocation_key *net_device_val::ring_key_redirection_reserve(resource_allocation_key *key)
{
    // if allocation logic is usr idx feature disabled
    if (!safe_mce_sys().ring_limit_per_interface ||
        key->get_ring_alloc_logic() == RING_LOGIC_PER_USER_ID) {
        return key;
    }

    if (m_h_ring_key_redirection_map.find(key) != m_h_ring_key_redirection_map.end()) {
        m_h_ring_key_redirection_map[key].second++;
        nd_logdbg("redirecting key=%s (ref-count:%d) to key=%s", key->to_str().c_str(),
                  m_h_ring_key_redirection_map[key].second,
                  m_h_ring_key_redirection_map[key].first->to_str().c_str());
        return m_h_ring_key_redirection_map[key].first;
    }

    int ring_map_size = (int)m_h_ring_map.size();
    if (safe_mce_sys().ring_limit_per_interface > ring_map_size) {
        resource_allocation_key *key2 = new resource_allocation_key(*key);
        // replace key to redirection key
        key2->set_user_id_key(ring_map_size);
        m_h_ring_key_redirection_map[key] = std::make_pair(key2, 1);
        nd_logdbg("redirecting key=%s (ref-count:1) to key=%s", key->to_str().c_str(),
                  key2->to_str().c_str());
        return key2;
    }

    rings_hash_map_t::iterator ring_iter = m_h_ring_map.begin();
    int min_ref_count = ring_iter->second.second;
    resource_allocation_key *min_key = ring_iter->first;
    while (ring_iter != m_h_ring_map.end()) {
        if (ring_iter->second.second < min_ref_count) {
            min_ref_count = ring_iter->second.second;
            min_key = ring_iter->first;
        }
        ring_iter++;
    }
    m_h_ring_key_redirection_map[key] = std::make_pair(new resource_allocation_key(*min_key), 1);
    nd_logdbg("redirecting key=%s (ref-count:1) to key=%s", key->to_str().c_str(),
              min_key->to_str().c_str());
    return min_key;
}

resource_allocation_key *net_device_val::get_ring_key_redirection(resource_allocation_key *key)
{
    if (!safe_mce_sys().ring_limit_per_interface) {
        return key;
    }

    if (m_h_ring_key_redirection_map.find(key) == m_h_ring_key_redirection_map.end()) {
        nd_logdbg("key = %s is not found in the redirection map", key->to_str().c_str());
        return key;
    }

    return m_h_ring_key_redirection_map[key].first;
}

void net_device_val::ring_key_redirection_release(resource_allocation_key *key)
{
    if (safe_mce_sys().ring_limit_per_interface &&
        m_h_ring_key_redirection_map.find(key) != m_h_ring_key_redirection_map.end() &&
        --m_h_ring_key_redirection_map[key].second == 0) {
        // this is allocated in ring_key_redirection_reserve
        nd_logdbg("release redirecting key=%s (ref-count:%d) to key=%s", key->to_str().c_str(),
                  m_h_ring_key_redirection_map[key].second,
                  m_h_ring_key_redirection_map[key].first->to_str().c_str());
        delete m_h_ring_key_redirection_map[key].first;
        m_h_ring_key_redirection_map.erase(key);
    }
}

int net_device_val::global_ring_poll_and_process_element(uint64_t *p_poll_sn_rx,
                                                         uint64_t *p_poll_sn_tx,
                                                         void *pv_fd_ready_array /*=NULL*/)
{
    nd_logfuncall("");
    int ret_total = 0;
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    rings_hash_map_t::iterator ring_iter;
    for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
        int ret = THE_RING->poll_and_process_element_rx(p_poll_sn_rx, pv_fd_ready_array);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret < 0 && errno != EAGAIN) {
            nd_logerr("Error in RX ring->poll_and_process_element() of %p (errno=%d %s)", THE_RING,
                      errno, strerror(errno));
            return ret;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        if (ret > 0) {
            nd_logfunc("ring[%p] RX Returned with: %d (sn=%d)", THE_RING, ret, *p_poll_sn_rx);
            ret_total += ret;
        }
#if defined(DEFINED_FORCE_TX_POLLING)
        ret = THE_RING->poll_and_process_element_tx(p_poll_sn_tx);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret < 0 && errno != EAGAIN) {
            nd_logerr("Error in TX ring->poll_and_process_element() of %p (errno=%d %m)", THE_RING,
                      errno);
            return ret;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        if (ret > 0) {
            nd_logfunc("ring[%p] TX Returned with: %d (sn=%d)", THE_RING, ret, *p_poll_sn_tx);
            ret_total += ret;
        }
#endif /* DEFINED_FORCE_TX_POLLING */
    }
    return ret_total;
}

int net_device_val::global_ring_request_notification(uint64_t poll_sn_rx, uint64_t poll_sn_tx)
{
    int ret_total = 0;
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    rings_hash_map_t::iterator ring_iter;
    for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
        int ret = THE_RING->request_notification(CQT_RX, poll_sn_rx);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret < 0) {
            nd_logerr("Error RX ring[%p]->request_notification() (errno=%d %s)", THE_RING, errno,
                      strerror(errno));
            return ret;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        nd_logfunc("ring[%p] RX Returned with: %d (sn=%d)", THE_RING, ret, poll_sn_rx);
        ret_total += ret;
#if defined(DEFINED_FORCE_TX_POLLING)
        ret = THE_RING->request_notification(CQT_TX, poll_sn_tx);
        BULLSEYE_EXCLUDE_BLOCK_START
        if (ret < 0) {
            nd_logerr("Error TX ring[%p]->request_notification() (errno=%d %m)", THE_RING, errno);
            return ret;
        }
        BULLSEYE_EXCLUDE_BLOCK_END
        nd_logfunc("ring[%p] TX Returned with: %d (sn=%d)", THE_RING, ret, poll_sn_tx);
        ret_total += ret;
#endif /* DEFINED_FORCE_TX_POLLING */
    }
    return ret_total;
}

int net_device_val::ring_drain_and_proccess()
{
    nd_logfuncall();
    int ret_total = 0;

    std::lock_guard<decltype(m_lock)> lock(m_lock);
    rings_hash_map_t::iterator ring_iter;
    for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
        int ret = THE_RING->drain_and_proccess();
        if (ret < 0) {
            return ret;
        }
        if (ret > 0) {
            nd_logfunc("cq[%p] Returned with: %d", THE_RING, ret);
        }
        ret_total += ret;
    }
    return ret_total;
}

void net_device_val::ring_adapt_cq_moderation()
{
    nd_logfuncall();

    std::lock_guard<decltype(m_lock)> lock(m_lock);
    rings_hash_map_t::iterator ring_iter;
    for (ring_iter = m_h_ring_map.begin(); ring_iter != m_h_ring_map.end(); ring_iter++) {
        THE_RING->adapt_cq_moderation();
    }
}

void net_device_val::ring_clear_all_rfs()
{
    nd_logfuncall();
    std::lock_guard<decltype(m_lock)> lock(m_lock);
    for (auto &itr : m_h_ring_map) {
        itr.second.first->flow_del_all_rfs_safe();
    }
}

void net_device_val::register_to_ibverbs_events(event_handler_ibverbs *handler)
{
    for (size_t i = 0; i < m_slaves.size(); i++) {
        bool found = false;
        for (size_t j = 0; j < i; j++) {
            if (m_slaves[i]->p_ib_ctx == m_slaves[j]->p_ib_ctx) {
                found =
                    true; // two slaves might be on two ports of the same device, register only once
                break;
            }
        }
        if (found) {
            continue;
        }
        nd_logfunc("registering slave to ibverbs events slave=%p", m_slaves[i]);
        g_p_event_handler_manager->register_ibverbs_event(
            m_slaves[i]->p_ib_ctx->get_ibv_context()->async_fd, handler,
            m_slaves[i]->p_ib_ctx->get_ibv_context(), 0);
    }
}

void net_device_val::unregister_to_ibverbs_events(event_handler_ibverbs *handler)
{
    for (size_t i = 0; i < m_slaves.size(); i++) {
        bool found = false;
        for (size_t j = 0; j < i; j++) {
            if (m_slaves[i]->p_ib_ctx == m_slaves[j]->p_ib_ctx) {
                found = true; // two slaves might be on two ports of the same device, unregister
                              // only once
                break;
            }
        }
        if (found) {
            continue;
        }
        nd_logfunc("unregistering slave to ibverbs events slave=%p", m_slaves[i]);
        g_p_event_handler_manager->unregister_ibverbs_event(
            m_slaves[i]->p_ib_ctx->get_ibv_context()->async_fd, handler);
    }
}

void net_device_val_eth::configure()
{
    m_p_L2_addr = create_L2_address(get_ifname());

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_p_L2_addr) {
        nd_logpanic("m_p_L2_addr allocation error");
    }
    BULLSEYE_EXCLUDE_BLOCK_END

    create_br_address(get_ifname());

    m_vlan = get_vlan_id_from_ifname(get_ifname());
    if (m_vlan) {
        parse_prio_egress_map();
    }
    if (m_vlan && m_bond != NO_BOND && m_bond_fail_over_mac == 1) {
        vlog_printf(VLOG_WARNING,
                    " ******************************************************************\n");
        vlog_printf(VLOG_WARNING, "%s: vlan over bond while fail_over_mac=1 is not offloaded\n",
                    get_ifname());
        vlog_printf(VLOG_WARNING,
                    " ******************************************************************\n");
        m_state = INVALID;
    }
    if (!m_vlan && (get_flags() & IFF_MASTER)) {
        char if_name[IFNAMSIZ] = {0};

        if (!if_indextoname(m_slaves[0]->if_index, if_name)) {
            nd_logerr("Can not find interface name by index=%d", m_slaves[0]->if_index);
        }

        // in case vlan is configured on slave
        m_vlan = get_vlan_id_from_ifname(if_name);
    }
}

uint32_t net_device_val::get_priority_by_tc_class(uint32_t tc_class)
{
    tc_class_priority_map::iterator it = m_class_prio_map.find(tc_class);
    if (it == m_class_prio_map.end()) {
        return DEFAULT_ENGRESS_MAP_PRIO;
    }
    return it->second;
}

void net_device_val_eth::parse_prio_egress_map()
{
    int len, ret;
    nl_cache *cache = nullptr;
    rtnl_link *link;
    vlan_map *map;

    nl_sock *socket = nl_socket_alloc();
    if (!socket) {
        nd_logdbg("unable to allocate a netlink socket");
        goto out;
    }
    nl_socket_set_local_port(socket, 0);
    ret = nl_connect(socket, NETLINK_ROUTE);
    if (ret < 0) {
        nd_logdbg("unable to connect to libnl socket %d (errno=%d)", ret, errno);
        goto out;
    }
    ret = rtnl_link_alloc_cache(socket, AF_UNSPEC, &cache);
    if (ret < 0 || !cache) {
        nd_logdbg("unable to create libnl cache %d (errno=%d)", ret, errno);
        goto out;
    }
    link = rtnl_link_get_by_name(cache, get_ifname());
    if (!link) {
        nd_logdbg("unable to find libnl link");
        goto out;
    }
    map = rtnl_link_vlan_get_egress_map(link, &len);
    if (!map || !len) {
        nd_logdbg("no egress map found %d %p", len, map);
        goto out;
    }
    for (int i = 0; i < len; i++) {
        m_class_prio_map[map[i].vm_from] = map[i].vm_to;
    }
out:
    if (cache) {
        nl_cache_free(cache);
    }
    if (socket) {
        nl_socket_free(socket);
    }
}

ring *net_device_val_eth::create_ring(resource_allocation_key *key)
{
    ring *ring = nullptr;

    try {
        switch (m_bond) {
        case NO_BOND:
            ring = new ring_eth(get_if_idx(), nullptr, RING_ETH, true,
                                (key ? key->get_use_locks() : true));
            break;
        case ACTIVE_BACKUP:
        case LAG_8023ad:
            ring = new ring_bond_eth(get_if_idx());
            break;
        case NETVSC:
            ring = new ring_bond_netvsc(get_if_idx());
            break;
        default:
            nd_logdbg("Unknown ring type");
            break;
        }
    } catch (xlio_error &error) {
        nd_logdbg("failed creating ring %s", error.message);
    }

    return ring;
}

L2_address *net_device_val_eth::create_L2_address(const char *ifname)
{
    if (m_p_L2_addr) {
        delete m_p_L2_addr;
        m_p_L2_addr = nullptr;
    }
    unsigned char hw_addr[ETH_ALEN];
    get_local_ll_addr(ifname, hw_addr, ETH_ALEN, false);
    return new ETH_addr(hw_addr);
}

void net_device_val_eth::create_br_address(const char *ifname)
{
    if (m_p_br_addr) {
        delete m_p_br_addr;
        m_p_br_addr = nullptr;
    }
    uint8_t hw_addr[ETH_ALEN];
    get_local_ll_addr(ifname, hw_addr, ETH_ALEN, true);
    m_p_br_addr = new ETH_addr(hw_addr);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!m_p_br_addr) {
        nd_logpanic("m_p_br_addr allocation error");
    }
    BULLSEYE_EXCLUDE_BLOCK_END
}
const std::string net_device_val_eth::to_str() const
{
    return std::string("ETH: " + net_device_val::to_str());
}

bool net_device_val::verify_bond_or_eth_qp_creation()
{
    char slaves[IFNAMSIZ * MAX_SLAVES] = {0};

    if (!get_bond_slaves_name_list(get_ifname_link(), slaves, sizeof slaves)) {
        vlog_printf(VLOG_WARNING,
                    "******************************************************************************"
                    "*************************\n");
        vlog_printf(
            VLOG_WARNING,
            "* Interface %s will not be offloaded, slave list or bond name could not be found\n",
            get_ifname());
        vlog_printf(VLOG_WARNING,
                    "******************************************************************************"
                    "*************************\n");
        return false;
    }
    // go over all slaves and check preconditions
    bool bond_ok = true;
    char *slave_name;
    char *save_ptr;
    slave_name = strtok_r(slaves, " ", &save_ptr);
    while (slave_name) {
        char *p = strchr(slave_name, '\n');
        if (p) {
            *p = '\0'; // Remove the tailing 'new line" char
        }
        if (!verify_eth_qp_creation(slave_name)) {
            // check all slaves but print only once for bond
            bond_ok = false;
        }
        slave_name = strtok_r(nullptr, " ", &save_ptr);
    }
    if (!bond_ok) {
        vlog_printf(VLOG_WARNING,
                    "******************************************************************************"
                    "*************************\n");
        vlog_printf(VLOG_WARNING,
                    "* Bond %s will not be offloaded due to problem with its slaves.\n",
                    get_ifname());
        vlog_printf(VLOG_WARNING, "* Check warning messages for more information.\n");
        vlog_printf(VLOG_WARNING,
                    "******************************************************************************"
                    "*************************\n");
    } else {
#if defined(DEFINED_ROCE_LAG)
        /* Sanity check for image guid is not correct
         * for RoCE LAG on upstream rdma-core
         */
#else
        /*
         * Print warning message while bond device contains two slaves of the same HCA
         * while RoCE LAG is enabled for both slaves.
         */
        sys_image_guid_map_t::iterator guid_iter;
        for (guid_iter = m_sys_image_guid_map.begin(); guid_iter != m_sys_image_guid_map.end();
             guid_iter++) {
            char bond_roce_lag_path[256] = {0};
            if (guid_iter->second.size() > 1 &&
                check_bond_roce_lag_exist(bond_roce_lag_path, sizeof(bond_roce_lag_path),
                                          guid_iter->second.front().c_str()) &&
                check_bond_roce_lag_exist(bond_roce_lag_path, sizeof(bond_roce_lag_path),
                                          guid_iter->second.back().c_str())) {
                print_roce_lag_warnings(get_ifname_link(), bond_roce_lag_path,
                                        guid_iter->second.front().c_str(),
                                        guid_iter->second.back().c_str());
            }
        }
#endif /* DEFINED_ROCE_LAG */
    }
    return bond_ok;
}

// interface name can be slave while ifa struct can describe bond
bool net_device_val::verify_eth_qp_creation(const char *interface_name)
{
    if (m_type == ARPHRD_ETHER) {
        if (verify_qp_creation(interface_name, IBV_QPT_RAW_PACKET)) {
            return true;
        }
    }
    return false;
}

// ifname should point to a physical device
bool net_device_val::verify_qp_creation(const char *ifname, enum ibv_qp_type qp_type)
{
    bool success = false;
    char bond_roce_lag_path[256] = {0};
    struct ibv_cq *cq = nullptr;
    struct ibv_comp_channel *channel = nullptr;
    struct ibv_qp *qp = nullptr;
    struct ibv_context *context;
    int comp_vector = 0;

    xlio_ibv_qp_init_attr qp_init_attr;
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));

    xlio_ibv_cq_init_attr attr;
    memset(&attr, 0, sizeof(attr));

    qp_init_attr.cap.max_send_wr = 2048;
    qp_init_attr.cap.max_recv_wr = MCE_DEFAULT_RX_NUM_WRE;
    qp_init_attr.cap.max_inline_data = MCE_DEFAULT_TX_MAX_INLINE;
    qp_init_attr.cap.max_send_sge = MCE_DEFAULT_TX_NUM_SGE;
    qp_init_attr.cap.max_recv_sge = MCE_DEFAULT_RX_NUM_SGE;
    qp_init_attr.sq_sig_all = 0;
    qp_init_attr.qp_type = qp_type;

    // find ib_cxt
    char base_ifname[IFNAMSIZ];
    get_base_interface_name((const char *)(ifname), base_ifname, sizeof(base_ifname));
    int port_num = get_port_from_ifname(base_ifname);
    ib_ctx_handler *p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(base_ifname);

    if (!p_ib_ctx) {
        nd_logdbg("Cant find ib_ctx for interface %s", base_ifname);
        if (qp_type == IBV_QPT_RAW_PACKET && m_bond != NO_BOND) {
            if (check_bond_roce_lag_exist(bond_roce_lag_path, sizeof(bond_roce_lag_path), ifname)) {
                print_roce_lag_warnings(get_ifname_link(), bond_roce_lag_path);
            } else if ((p_ib_ctx = g_p_ib_ctx_handler_collection->get_ib_ctx(get_ifname_link())) &&
                       strstr(p_ib_ctx->get_ibname().c_str(), "bond")) {
                print_roce_lag_warnings(get_ifname_link());
            }
        }
        goto release_resources;
    } else if (port_num > p_ib_ctx->get_ibv_device_attr()->phys_port_cnt) {
        nd_logdbg("Invalid port for interface %s", base_ifname);
        if (qp_type == IBV_QPT_RAW_PACKET && m_bond != NO_BOND && p_ib_ctx->is_mlx4()) {
            print_roce_lag_warnings(get_ifname_link());
        }
        goto release_resources;
    }

    // Add to guid map in order to detect roce lag issue
    if (qp_type == IBV_QPT_RAW_PACKET && m_bond != NO_BOND) {
        m_sys_image_guid_map[p_ib_ctx->get_ibv_device_attr()->sys_image_guid].push_back(
            base_ifname);
    }

    // create qp resources
    channel = ibv_create_comp_channel(p_ib_ctx->get_ibv_context());
    if (!channel) {
        nd_logdbg("channel creation failed for interface %s (errno=%d %s)", ifname, errno,
                  strerror(errno));
        goto release_resources;
    }
    VALGRIND_MAKE_MEM_DEFINED(channel, sizeof(ibv_comp_channel));
    context = p_ib_ctx->get_ibv_context();
    cq = xlio_ibv_create_cq(context, safe_mce_sys().tx_num_wr, (void *)this, channel, comp_vector,
                            &attr);
    if (!cq) {
        nd_logdbg("cq creation failed for interface %s (errno=%d %s)", ifname, errno,
                  strerror(errno));
        goto release_resources;
    }

    xlio_ibv_qp_init_attr_comp_mask(p_ib_ctx->get_ibv_pd(), qp_init_attr);
    qp_init_attr.recv_cq = cq;
    qp_init_attr.send_cq = cq;

    qp = xlio_ibv_create_qp(p_ib_ctx->get_ibv_pd(), &qp_init_attr);
    if (qp) {
        success = true;
        if (qp_type == IBV_QPT_RAW_PACKET && p_ib_ctx->is_packet_pacing_supported() &&
            !priv_ibv_query_burst_supported(qp, port_num)) {
            p_ib_ctx->set_burst_capability(true);
        }
        nd_logdbg("verified interface %s for burst capabilities : %s", ifname,
                  p_ib_ctx->get_burst_capability() ? "enabled" : "disabled");
    } else {
        nd_logdbg("QP creation failed on interface %s (errno=%d %s), Traffic will not be offloaded",
                  ifname, errno, strerror(errno));

        int err = errno; // verify_raw_qp_privliges can overwrite errno so keep it before the call
        if (validate_user_has_cap_net_raw_privliges() == 0 || err == EPERM) {
            vlog_printf(VLOG_WARNING,
                        "**************************************************************************"
                        "*****************************\n");
            vlog_printf(VLOG_WARNING, "* Interface %s will not be offloaded.\n", ifname);
            vlog_printf(VLOG_WARNING,
                        "* Offloaded resources are restricted to root or user with CAP_NET_RAW "
                        "privileges\n");
            vlog_printf(VLOG_WARNING,
                        "* Read the CAP_NET_RAW and root access section in the " PRODUCT_NAME
                        "'s User Manual for more information\n");
            vlog_printf(VLOG_WARNING,
                        "**************************************************************************"
                        "*****************************\n");
        } else {
            vlog_printf(VLOG_WARNING,
                        "**************************************************************************"
                        "*****************************\n");
            vlog_printf(VLOG_WARNING, "* Interface %s will not be offloaded.\n", ifname);
            vlog_printf(VLOG_WARNING,
                        "* " PRODUCT_NAME
                        " was not able to create QP for this device (errno = %d).\n",
                        err);
            vlog_printf(VLOG_WARNING,
                        "**************************************************************************"
                        "*****************************\n");
        }
    }

release_resources:
    if (qp) {
        IF_VERBS_FAILURE(ibv_destroy_qp(qp))
        {
            nd_logdbg("qp destroy failed on interface %s (errno=%d %s)", ifname, errno,
                      strerror(errno));
            success = false;
        }
        ENDIF_VERBS_FAILURE;
    }
    if (cq) {
        IF_VERBS_FAILURE(ibv_destroy_cq(cq))
        {
            nd_logdbg("cq destroy failed on interface %s (errno=%d %s)", ifname, errno,
                      strerror(errno));
            success = false;
        }
        ENDIF_VERBS_FAILURE;
    }
    if (channel) {
        IF_VERBS_FAILURE(ibv_destroy_comp_channel(channel))
        {
            nd_logdbg("channel destroy failed on interface %s (errno=%d %s)", ifname, errno,
                      strerror(errno));
            success = false;
        }
        ENDIF_VERBS_FAILURE;
        VALGRIND_MAKE_MEM_UNDEFINED(channel, sizeof(ibv_comp_channel));
    }
    return success;
}
