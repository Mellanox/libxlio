/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "mix_base.h"
#include "src/core/util/ip_address.h"

#define SOCKLEN4 static_cast<socklen_t>(sizeof(sockaddr_in))
#define SOCKLEN6 static_cast<socklen_t>(sizeof(sockaddr_in6))

class ip_address_test : public mix_base {
public:
    typedef union {
        in_addr m_1;
        in_addr_t m_2;
    } ip_v4;

    typedef union {
        in6_addr m_1;
        uint64_t m_2[2];
    } ip_v6;

    ip_v4 m_addr4;
    ip_v6 m_addr6;

    ip_address_test()
    {
        m_addr4.m_2 = 0xAAAA9999;
        m_addr6.m_2[0] = 0xEEEEEEEE99999999;
        m_addr6.m_2[1] = 0x99999999EEEEEEEE;
    }
};

TEST_F(ip_address_test, ip_address_ctors)
{
    ip_address sa2_4(m_addr4.m_2);
    in_addr_t temp = sa2_4.get_in_addr();
    EXPECT_EQ(0, memcmp(&temp, &m_addr4, sizeof(m_addr4)));
    ip_address sa1_4(m_addr4.m_1);
    EXPECT_EQ(0, memcmp(&sa1_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    ip_address sa1_6(m_addr6.m_1);
    EXPECT_EQ(0, memcmp(&sa1_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));

    ip_address sa3_4(sa1_4);
    EXPECT_EQ(0, memcmp(&sa3_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    ip_address sa3_6(sa1_6);
    EXPECT_EQ(0, memcmp(&sa3_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));

    ip_address sa4_4(std::move(sa3_4));
    EXPECT_EQ(0, memcmp(&sa4_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(0, memcmp(&sa3_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    ip_address sa4_6(std::move(sa3_6));
    EXPECT_EQ(0, memcmp(&sa4_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(0, memcmp(&sa3_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
}

TEST_F(ip_address_test, ip_address_getters)
{
    ip_address sa1_4(m_addr4.m_1);
    ip_address sa1_6(m_addr6.m_1);

    EXPECT_FALSE(sa1_4.is_mc(AF_INET));
    EXPECT_FALSE(sa1_6.is_mc(AF_INET6));

    ip_address sa2_4(sa1_4);
    ip_address sa2_6(sa1_6);
    EXPECT_TRUE(sa1_4 == sa2_4);
    EXPECT_TRUE(sa1_6 == sa2_6);

    ip_v4 addr4_2;
    ip_v6 addr6_2;
    addr4_2.m_2 = 0x9999AAAA;
    addr6_2.m_2[0] = 0x99999999EEEEEEEE;
    addr6_2.m_2[1] = 0xEEEEEEEE99999999;
    ip_address sa3_4(addr4_2.m_1);
    ip_address sa3_6(addr6_2.m_1);
    EXPECT_TRUE(sa2_4 != sa3_4);
    EXPECT_TRUE(sa2_6 != sa3_6);
    EXPECT_TRUE(sa3_4 != sa3_6);

    // EXPECT_EQ(11ULL, sa1_4.hash());
    // EXPECT_EQ(199ULL, sa1_6.hash());

    // Test garbage space to be nullified in case of IPv4.
    ip_v6 addr6_4 = {.m_2 = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}};
    ip_address sa4_4(addr6_4.m_1);
    ip_address sa5_4(addr6_2.m_1);
    EXPECT_TRUE(sa4_4 != sa5_4);
    new (&sa4_4) ip_address(m_addr4.m_1);
    new (&sa5_4) ip_address(m_addr4.m_1);
    EXPECT_TRUE(sa4_4 == sa5_4);
}

TEST_F(ip_address_test, ip_address_setters)
{
    ip_address sa1(m_addr4.m_1);

    ip_v4 addr4_1;
    ip_v6 addr6_1;
    addr4_1.m_2 = 0x010404E0;
    addr6_1.m_2[0] = 0xAAAAAAAA000000FF;
    addr6_1.m_2[1] = 0x0;

    sa1 = ip_address(addr6_1.m_1);
    EXPECT_EQ(0, memcmp(&sa1.get_in6_addr(), &addr6_1, sizeof(addr6_1)));
    // EXPECT_TRUE(sa1.is_mc(AF_INET6));
    sa1 = ip_address(addr4_1.m_1);
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    EXPECT_TRUE(sa1.is_mc(AF_INET));

    ip_address sa2(addr4_1.m_1);
    sa1 = ip_address(addr6_1.m_1);
    sa1 = std::move(sa2);
    EXPECT_EQ(0, memcmp(&sa2.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    sa1 = ip_address(addr6_1.m_1);
    sa2 = std::move(sa1);
    EXPECT_EQ(0, memcmp(&sa2.get_in4_addr(), &addr6_1, sizeof(addr6_1)));
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr6_1, sizeof(addr6_1)));
}

TEST_F(ip_address_test, ip_address_strings)
{
    ip_address sa1_4(m_addr4.m_1);
    ip_address sa1_6(m_addr6.m_1);

    EXPECT_TRUE(sa1_4.to_str(AF_INET) == "153.153.170.170");
    EXPECT_TRUE(sa1_6.to_str(AF_INET6) == "[9999:9999:eeee:eeee:eeee:eeee:9999:9999]");

    ip_v6 addr6;
    addr6.m_2[0] = 0xBBFF000000000000;
    addr6.m_2[1] = 0x0;
    sa1_6 = ip_address(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str(AF_INET6) == "[0:0:0:ffbb::]");
    addr6.m_2[0] = 0x0;
    addr6.m_2[1] = 0x0;
    sa1_6 = ip_address(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str(AF_INET6) == "[::]");
    addr6.m_2[0] = 0x0;
    addr6.m_2[1] = 0x9999AAAAFFFF0000;
    sa1_6 = ip_address(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str(AF_INET6) == "[::ffff:170.170.153.153]");
}

TEST_F(ip_address_test, ip_addr_ctors)
{
    ip_addr sa2_4(m_addr4.m_2);
    in_addr_t temp = sa2_4.get_in_addr();
    EXPECT_EQ(0, memcmp(&temp, &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(sa2_4.get_family(), AF_INET);
    ip_addr sa1_4(m_addr4.m_1);
    EXPECT_EQ(0, memcmp(&sa1_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(sa1_4.get_family(), AF_INET);
    ip_addr sa1_6(m_addr6.m_1);
    EXPECT_EQ(0, memcmp(&sa1_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(sa1_6.get_family(), AF_INET6);

    ip_addr sa3_4(sa1_4);
    EXPECT_EQ(0, memcmp(&sa3_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(sa3_4.get_family(), AF_INET);
    ip_addr sa3_6(sa1_6);
    EXPECT_EQ(0, memcmp(&sa3_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(sa3_6.get_family(), AF_INET6);

    ip_addr sa4_4(std::move(sa3_4));
    EXPECT_EQ(0, memcmp(&sa4_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(0, memcmp(&sa3_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(sa4_4.get_family(), AF_INET);
    EXPECT_EQ(sa3_4.get_family(), AF_INET);
    ip_addr sa4_6(std::move(sa3_6));
    EXPECT_EQ(0, memcmp(&sa4_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(0, memcmp(&sa3_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(sa4_6.get_family(), AF_INET6);
    EXPECT_EQ(sa3_6.get_family(), AF_INET6);

    ip_address sa5_4(m_addr4.m_1);
    ip_address sa5_6(m_addr6.m_1);

    ip_addr sa6_4(sa5_4, AF_INET);
    EXPECT_EQ(0, memcmp(&sa6_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(sa6_4.get_family(), AF_INET);
    EXPECT_TRUE(sa6_4.is_ipv4());
    EXPECT_FALSE(sa6_4.is_ipv6());
    ip_addr sa6_6(sa5_6, AF_INET6);
    EXPECT_EQ(0, memcmp(&sa6_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(sa6_6.get_family(), AF_INET6);
    EXPECT_TRUE(sa6_6.is_ipv6());
    EXPECT_FALSE(sa6_6.is_ipv4());

    ip_addr sa7_4(std::move(sa5_4), AF_INET);
    EXPECT_EQ(0, memcmp(&sa7_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(0, memcmp(&sa5_4.get_in4_addr(), &m_addr4, sizeof(m_addr4)));
    EXPECT_EQ(sa7_4.get_family(), AF_INET);
    EXPECT_TRUE(sa7_4.is_ipv4());
    EXPECT_FALSE(sa7_4.is_ipv6());
    ip_addr sa7_6(std::move(sa5_6), AF_INET6);
    EXPECT_EQ(0, memcmp(&sa7_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(0, memcmp(&sa5_6.get_in6_addr(), &m_addr6, sizeof(m_addr6)));
    EXPECT_EQ(sa7_6.get_family(), AF_INET6);
    EXPECT_TRUE(sa7_6.is_ipv6());
    EXPECT_FALSE(sa7_6.is_ipv4());
}

TEST_F(ip_address_test, ip_addr_getters)
{
    ip_addr sa1_4(m_addr4.m_1);
    ip_addr sa1_6(m_addr6.m_1);
    ip_addr sa2_4(sa1_4);
    ip_addr sa2_6(sa1_6);
    EXPECT_TRUE(sa1_4 == sa2_4);
    EXPECT_TRUE(sa1_6 == sa2_6);

    ip_v4 addr4_2;
    ip_v6 addr6_2;
    addr4_2.m_2 = 0x9999AAAA;
    addr6_2.m_2[0] = 0x99999999EEEEEEEE;
    addr6_2.m_2[1] = 0xEEEEEEEE99999999;
    ip_addr sa3_4(addr4_2.m_1);
    ip_addr sa3_6(addr6_2.m_1);
    EXPECT_TRUE(sa2_4 != sa3_4);
    EXPECT_TRUE(sa2_6 != sa3_6);
    EXPECT_TRUE(sa3_4 != sa3_6);

    // EXPECT_EQ(11ULL, sa1_4.hash());
    // EXPECT_EQ(199ULL, sa1_6.hash());

    // Test garbage space to be nullified in case of IPv4.
    ip_v6 addr6_4 = {.m_2 = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}};
    ip_addr sa4_4(addr6_4.m_1);
    ip_addr sa5_4(addr6_2.m_1);
    EXPECT_TRUE(sa4_4 != sa5_4);
    new (&sa4_4) ip_addr(m_addr4.m_1);
    new (&sa5_4) ip_addr(m_addr4.m_1);
    EXPECT_TRUE(sa4_4 == sa5_4);

    ip_addr sa6_6(m_addr6.m_1);
    ip_addr sa6_4(reinterpret_cast<const in_addr &>(m_addr6.m_1));
    EXPECT_TRUE(sa6_4 != sa6_6);

    ip_addr sa7_4(m_addr6.m_1, AF_INET);
    ip_addr sa7_6(m_addr6.m_1, AF_INET6);
    EXPECT_TRUE(sa7_4 != sa7_6);
}

TEST_F(ip_address_test, ip_addr_setters)
{
    ip_addr sa1(m_addr4.m_1);

    ip_v4 addr4_1;
    ip_v6 addr6_1;
    addr4_1.m_2 = 0x010404E0;
    addr6_1.m_2[0] = 0xAAAAAAAA000000FF;
    addr6_1.m_2[1] = 0x0;

    sa1 = ip_addr(addr6_1.m_1);
    EXPECT_EQ(0, memcmp(&sa1.get_in6_addr(), &addr6_1, sizeof(addr6_1)));
    EXPECT_EQ(sa1.get_family(), AF_INET6);

    sa1 = ip_addr(addr4_1.m_1);
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    EXPECT_EQ(sa1.get_family(), AF_INET);

    ip_addr sa2(addr4_1.m_1);
    sa1 = ip_addr(addr6_1.m_1);
    EXPECT_EQ(sa1.get_family(), AF_INET6);
    sa1 = std::move(sa2);
    EXPECT_EQ(sa1.get_family(), sa2.get_family());
    EXPECT_EQ(0, memcmp(&sa2.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr4_1, sizeof(addr4_1)));
    sa1 = ip_addr(addr6_1.m_1);
    EXPECT_EQ(sa1.get_family(), AF_INET6);
    sa2 = std::move(sa1);
    EXPECT_EQ(sa1.get_family(), sa2.get_family());
    EXPECT_EQ(0, memcmp(&sa2.get_in4_addr(), &addr6_1, sizeof(addr6_1)));
    EXPECT_EQ(0, memcmp(&sa1.get_in4_addr(), &addr6_1, sizeof(addr6_1)));
}

TEST_F(ip_address_test, ip_addr_strings)
{
    ip_addr sa1_4(m_addr4.m_1);
    ip_addr sa1_6(m_addr6.m_1);

    EXPECT_TRUE(sa1_4.to_str() == "153.153.170.170");
    EXPECT_TRUE(sa1_6.to_str() == "[9999:9999:eeee:eeee:eeee:eeee:9999:9999]");

    ip_v6 addr6;
    addr6.m_2[0] = 0xBBFF000000000000;
    addr6.m_2[1] = 0x0;
    sa1_6 = ip_addr(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str() == "[0:0:0:ffbb::]");
    addr6.m_2[0] = 0x0;
    addr6.m_2[1] = 0x0;
    sa1_6 = ip_addr(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str() == "[::]");
    addr6.m_2[0] = 0x0;
    addr6.m_2[1] = 0x9999AAAAFFFF0000;
    sa1_6 = ip_addr(addr6.m_1);
    EXPECT_TRUE(sa1_6.to_str() == "[::ffff:170.170.153.153]");
}

TEST_F(ip_address_test, mapped_ipv4)
{
    ip_v6 mapped_addr;
    mapped_addr.m_2[0] = mapped_addr.m_2[1] = 0x0ULL;
    uint16_t *raw16 = reinterpret_cast<uint16_t *>(mapped_addr.m_2 + 1);
    raw16[1] = 0xFFFFU;
    raw16[2] = htons(0x7F01);
    raw16[3] = htons(0x8001);

    ip_address ip_mapped(mapped_addr.m_1);
    EXPECT_TRUE(ip_mapped.is_mapped_ipv4());
    EXPECT_TRUE(ip_mapped.to_str(AF_INET6) == "[::ffff:127.1.128.1]");

    ip_address sa1_4(m_addr4.m_1);
    ip_address to_mapped(sa1_4.to_mapped_ipv4());
    EXPECT_TRUE(to_mapped.is_mapped_ipv4());
    EXPECT_TRUE(to_mapped.to_str(AF_INET6) == "[::ffff:153.153.170.170]");
}

#include "src/core/util/xlio_stats.h"
#include "src/stats/stats_data_reader.h"
#include <sstream>
using std::ostream;

class stats_base : public testing::Test {
public:
    std::stringstream out;
    uint8_t buffer[sizeof(sh_mem_t) + sizeof(socket_instance_block_t) * 15];
    sh_mem_t &mem;
    stats_base()
        : buffer()
        , mem(*reinterpret_cast<sh_mem_t *>(buffer))
    {
        mem.reset();
#ifdef DEFINED_UTLS
        mem.ring_inst_arr[0].b_enabled = true;
        mem.ring_inst_arr[0].ring_stats.n_tx_tls_contexts = 1;
        mem.ring_inst_arr[0].ring_stats.n_rx_tls_contexts = 10;
        mem.ring_inst_arr[NUM_OF_SUPPORTED_RINGS - 1].b_enabled = true;
        mem.ring_inst_arr[NUM_OF_SUPPORTED_RINGS - 1].ring_stats.n_tx_tls_contexts = 102;
        mem.ring_inst_arr[NUM_OF_SUPPORTED_RINGS - 1].ring_stats.n_rx_tls_contexts = 120;
#endif /* DEFINED_UTLS */

        mem.skt_inst_arr[0].b_enabled = true;
        mem.skt_inst_arr[0].skt_stats.listen_counters =
            socket_listen_counters_t {1, 1, 2, 3, 5, 8, 13};
        mem.skt_inst_arr[0].skt_stats.sa_family = AF_INET;
        mem.skt_inst_arr[15].b_enabled = true;
        mem.skt_inst_arr[15].skt_stats.listen_counters =
            socket_listen_counters_t {21, 34, 55, 89, 144, 233, 377};
        mem.skt_inst_arr[15].skt_stats.sa_family = AF_INET;
        mem.skt_inst_arr[11].b_enabled = true;
        mem.skt_inst_arr[11].skt_stats.listen_counters =
            socket_listen_counters_t {21, 34, 55, 89, 144, 233, 377};
        mem.skt_inst_arr[11].skt_stats.sa_family = AF_INET6;
        mem.max_skt_inst_num = 16;
    }

protected:
    void SetUp() override { out.str(""); }
};

#ifdef DEFINED_UTLS

TEST_F(stats_base, ts_tls_presenter_entry_null_sh_mem)
{
    tls_context_counters_show comb;

    out << comb.update(nullptr);
    ASSERT_NE(out.str().find("0,0"), std::string::npos) << out.str();
    ASSERT_GE(out.str().size(), std::string("0,0").size()) << out.str();
}

TEST_F(stats_base, ts_tls_presenter_delta_mode)
{
    tls_context_counters_show comb(true);

    comb.update(&mem);
    out << comb.update(&mem);
    ASSERT_NE(out.str().find("0,0"), std::string::npos) << out.str();
}

TEST_F(stats_base, ts_tls_presenter_total_mode)
{
    tls_context_counters_show comb(false);

    out << comb.update(&mem);
    ASSERT_NE(out.str().find("103,130"), std::string::npos) << out.str();
}
#endif /* DEFINED_UTLS */

TEST_F(stats_base, socket_listen_counter_resenter_entry_delta_mode)
{
    socket_listen_counter_aggregate repr(true);
    out << repr.update(&mem);

    ASSERT_NE(out.str().find("22,35,57,92,149,241,390,21,34,55,89,144,233,377"), std::string::npos)
        << out.str();
    out.str("");
    out << repr.update(&mem);
    ASSERT_NE(out.str().find("0,0,0,0,0,0,0,0,0,0,0,0,0,0"), std::string::npos) << out.str();
}

TEST_F(stats_base, socket_listen_counter_resenter_entry_total_mode)
{
    socket_listen_counter_aggregate repr(false);
    out << repr.update(&mem);
    ASSERT_NE(out.str().find("22,35,57,92,149,241,390,21,34,55,89,144,233,377"), std::string::npos)
        << out.str();
    out.str("");
    out << repr.update(&mem);
    ASSERT_NE(out.str().find("22,35,57,92,149,241,390,21,34,55,89,144,233,377"), std::string::npos)
        << out.str();
}
