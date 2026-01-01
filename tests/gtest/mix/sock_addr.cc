/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "mix_base.h"
#include "src/core/util/sock_addr.h"

#define SOCKLEN4 static_cast<socklen_t>(sizeof(sockaddr_in))
#define SOCKLEN6 static_cast<socklen_t>(sizeof(sockaddr_in6))

class sock_addr_test : public mix_base {
public:
    sockaddr_in m_sockaddr4_1 = {.sin_family = AF_INET,
                                 .sin_port = 0x9,
                                 .sin_addr = {},
                                 .sin_zero = {}};

    sockaddr_in6 m_sockaddr6_1 = {.sin6_family = AF_INET6,
                                  .sin6_port = 0xCD,
                                  .sin6_flowinfo = 0xBBBBDDDD,
                                  .sin6_addr = {},
                                  .sin6_scope_id = 0xDDDDBBBB};

    uint32_t m_addr4_1 = 0xAAAA9999;
    uint64_t m_addr6_1[2] = {0xEEEEEEEE99999999, 0x99999999EEEEEEEE};

    sock_addr_test()
    {
        memcpy(&m_sockaddr4_1.sin_addr, &m_addr4_1, sizeof(m_addr4_1));
        memcpy(&m_sockaddr6_1.sin6_addr, &m_addr6_1, sizeof(m_addr6_1));
    }
};

TEST_F(sock_addr_test, sock_addr_ctors)
{
    uint8_t buf[sizeof(sock_addr)];
    sock_addr sa1;
    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(0, memcmp(sa1.get_p_sa(), buf, sizeof(sock_addr)));

    sock_addr sa2_4(reinterpret_cast<const sockaddr *>(&m_sockaddr4_1), SOCKLEN4);
    EXPECT_EQ(0, memcmp(sa2_4.get_p_sa(), &m_sockaddr4_1, SOCKLEN4));
    sock_addr sa2_6(reinterpret_cast<const sockaddr *>(&m_sockaddr6_1), SOCKLEN6);
    EXPECT_EQ(0, memcmp(sa2_6.get_p_sa(), &m_sockaddr6_1, SOCKLEN6));

    sock_addr sa3_4(sa2_4);
    EXPECT_EQ(0, memcmp(sa3_4.get_p_sa(), &m_sockaddr4_1, SOCKLEN4));
    sock_addr sa3_6(sa2_6);
    EXPECT_EQ(0, memcmp(sa3_6.get_p_sa(), &m_sockaddr6_1, SOCKLEN6));

    sockaddr_in6 sockaddr6_temp;
    memcpy(&sockaddr6_temp, &m_sockaddr6_1, SOCKLEN6);
    sockaddr6_temp.sin6_flowinfo = 0;
    sockaddr6_temp.sin6_scope_id = 0;
    sock_addr sa4_4(AF_INET, &m_sockaddr4_1.sin_addr, m_sockaddr4_1.sin_port);
    EXPECT_EQ(0, memcmp(sa4_4.get_p_sa(), &m_sockaddr4_1, SOCKLEN4));
    sock_addr sa4_6(AF_INET6, &m_sockaddr6_1.sin6_addr, m_sockaddr6_1.sin6_port);
    EXPECT_EQ(0, memcmp(sa4_6.get_p_sa(), &sockaddr6_temp, SOCKLEN6));
}

TEST_F(sock_addr_test, sock_addr_getters)
{
    sock_addr sa1_4(reinterpret_cast<const sockaddr *>(&m_sockaddr4_1), SOCKLEN4);
    sock_addr sa1_6(reinterpret_cast<const sockaddr *>(&m_sockaddr6_1), SOCKLEN6);

    sockaddr_in sockaddr4_temp;
    sa1_4.get_sa(reinterpret_cast<sockaddr *>(&sockaddr4_temp), SOCKLEN4);
    EXPECT_EQ(0, memcmp(&sockaddr4_temp, &m_sockaddr4_1, SOCKLEN4));
    sockaddr_in6 sockaddr6_temp;
    sa1_6.get_sa(reinterpret_cast<sockaddr *>(&sockaddr6_temp), SOCKLEN6);
    EXPECT_EQ(0, memcmp(&sockaddr6_temp, &m_sockaddr6_1, SOCKLEN6));

    EXPECT_EQ(AF_INET, get_sa_family(reinterpret_cast<sockaddr *>(&sockaddr4_temp)));
    EXPECT_EQ(AF_INET6, get_sa_family(reinterpret_cast<sockaddr *>(&sockaddr6_temp)));

    EXPECT_EQ(m_sockaddr4_1.sin_port,
              get_sa_port(reinterpret_cast<sockaddr *>(&sockaddr4_temp), sizeof(sockaddr4_temp)));
    EXPECT_EQ(m_sockaddr6_1.sin6_port,
              get_sa_port(reinterpret_cast<sockaddr *>(&sockaddr6_temp), sizeof(sockaddr6_temp)));

    EXPECT_EQ(AF_INET, sa1_4.get_sa_family());
    EXPECT_EQ(AF_INET6, sa1_6.get_sa_family());

    EXPECT_EQ(m_addr4_1, sa1_4.get_ip_addr().get_in_addr());
    // EXPECT_EQ(0, memcmp(&m_addr6_1, &sa1_6.get_ip_addr().get_in6_addr());

    EXPECT_EQ(m_sockaddr4_1.sin_port, sa1_4.get_in_port());
    EXPECT_EQ(m_sockaddr6_1.sin6_port, sa1_6.get_in_port());

    EXPECT_EQ(SOCKLEN4, sa1_4.get_socklen());
    EXPECT_EQ(SOCKLEN6, sa1_6.get_socklen());

    EXPECT_FALSE(sa1_4.is_anyaddr());
    EXPECT_FALSE(sa1_6.is_anyaddr());

    EXPECT_FALSE(sa1_4.is_mc());
    EXPECT_FALSE(sa1_6.is_mc());

    sock_addr sa2_4(sa1_4);
    sock_addr sa2_6(sa1_6);
    EXPECT_TRUE(sa1_4 == sa2_4);
    EXPECT_TRUE(sa1_6 == sa2_6);

    EXPECT_EQ(0xAAAA999900090002ULL, sa1_4.hash());
    EXPECT_EQ(0xCCCCAAAA77BA777DULL, sa1_6.hash());
}

TEST_F(sock_addr_test, sock_addr_setters)
{
    sock_addr sa1_4;
    sock_addr sa1_6;

    sa1_4.set_sockaddr(reinterpret_cast<const sockaddr *>(&m_sockaddr4_1), SOCKLEN4);
    sa1_6.set_sockaddr(reinterpret_cast<const sockaddr *>(&m_sockaddr6_1), SOCKLEN6);
    EXPECT_EQ(0, memcmp(sa1_4.get_p_sa(), &m_sockaddr4_1, SOCKLEN4));
    EXPECT_EQ(0, memcmp(sa1_6.get_p_sa(), &m_sockaddr6_1, SOCKLEN6));

    sock_addr sa2_4(sa1_4);
    sock_addr sa2_6(sa1_6);

    sa1_4.set_sa_family(AF_INET6);
    sa1_6.set_sa_family(AF_INET);
    EXPECT_EQ(sa1_4.get_p_sa()->sa_family, AF_INET6);
    EXPECT_EQ(sa1_6.get_p_sa()->sa_family, AF_INET);

    uint32_t mc4_ip = 0x010404E0;
    uint64_t mc6_ip[2] = {0xAAAAAAAA000000FF, 0x0};
    sa1_4.set_ip_port(AF_INET, &mc4_ip, m_sockaddr4_1.sin_port);
    sa1_6.set_ip_port(AF_INET6, &mc6_ip, m_sockaddr6_1.sin6_port);
    EXPECT_TRUE(sa1_4.is_mc());
    // EXPECT_TRUE(sa1_6.is_mc());

    ip_address ipaddr4(m_addr4_1);
    sa1_4.set_in_addr(ipaddr4);
    EXPECT_TRUE(ipaddr4 == sa1_4.get_ip_addr());
    // ip_address ipaddr6(m_addr6_1);
    // sa1_6.set_in_addr(ipaddr6);
    // EXPECT_TRUE(ipaddr6 == sa1_6.get_ip_addr());

    sa1_4 = sa2_4;
    EXPECT_TRUE(sa1_4 == sa2_4);
    sa1_6 = sa2_6;
    EXPECT_TRUE(sa1_6 == sa2_6);
}

TEST_F(sock_addr_test, sock_addr_strings)
{
    sock_addr sa1_4(reinterpret_cast<const sockaddr *>(&m_sockaddr4_1), SOCKLEN4);
    sock_addr sa1_6(reinterpret_cast<const sockaddr *>(&m_sockaddr6_1), SOCKLEN6);

    EXPECT_TRUE(
        sa1_4.to_str_ip_port() ==
        sockaddr2str(reinterpret_cast<const sockaddr *>(&m_sockaddr4_1), sizeof(m_sockaddr4_1)));
    EXPECT_TRUE(
        sa1_6.to_str_ip_port() ==
        sockaddr2str(reinterpret_cast<const sockaddr *>(&m_sockaddr6_1), sizeof(m_sockaddr6_1)));

    EXPECT_TRUE(sa1_4.to_str_port() == std::to_string(ntohs(m_sockaddr4_1.sin_port)));
    EXPECT_TRUE(sa1_6.to_str_port() == std::to_string(ntohs(m_sockaddr6_1.sin6_port)));

    EXPECT_TRUE(sa1_4.to_str_ip_port(true) == "153.153.170.170:2304");
    EXPECT_TRUE(sa1_6.to_str_ip_port(true) == "[9999:9999:eeee:eeee:eeee:eeee:9999:9999]:52480");
    uint64_t mc6_ip1[2] = {0xBBFF000000000000, 0x0};
    sa1_6.set_ip_port(AF_INET6, mc6_ip1, m_sockaddr6_1.sin6_port);
    EXPECT_TRUE(sa1_6.to_str_ip_port(true) == "[0:0:0:ffbb::]:52480");
    uint64_t mc6_ip2[2] = {0x0, 0x0};
    sa1_6.set_ip_port(AF_INET6, mc6_ip2, m_sockaddr6_1.sin6_port);
    EXPECT_TRUE(sa1_6.to_str_ip_port(true) == "[::]:52480");
    uint64_t mc6_ip3[2] = {0x0, 0x9999AAAAFFFF0000};
    sa1_6.set_ip_port(AF_INET6, mc6_ip3, m_sockaddr6_1.sin6_port);
    EXPECT_TRUE(sa1_6.to_str_ip_port(true) == "[::ffff:170.170.153.153]:52480");
}

TEST_F(sock_addr_test, mapped_ipv4)
{
    sock_addr sa1_4(reinterpret_cast<const sockaddr *>(&m_sockaddr4_1), SOCKLEN4);
    sockaddr_in6 out6_1;
    sockaddr_in out4_1;
    out6_1.sin6_family = AF_INET6;
    socklen_t out_len = 0U;

    sa1_4.get_sa_by_family(nullptr, out_len, AF_INET6);
    EXPECT_EQ(sizeof(sockaddr_in6), out_len);
    out_len = sizeof(sa_family_t);
    sa1_4.get_sa_by_family(reinterpret_cast<sockaddr *>(&out6_1), out_len, AF_INET6);
    EXPECT_EQ(0U, out6_1.sin6_family);
    EXPECT_EQ(sizeof(sockaddr_in6), out_len);
    out_len = sizeof(out6_1);
    sa1_4.get_sa_by_family(reinterpret_cast<sockaddr *>(&out6_1), out_len, AF_INET6);
    sock_addr out6_1_addr(reinterpret_cast<const sockaddr *>(&out6_1), sizeof(out6_1));
    EXPECT_TRUE(out6_1_addr.to_str_ip_port(true) == "[::ffff:153.153.170.170]:2304");
    EXPECT_EQ(sizeof(sockaddr_in6), out_len);

    out_len = 0U;
    sa1_4.get_sa_by_family(nullptr, out_len, AF_INET);
    EXPECT_EQ(sizeof(sockaddr_in), out_len);
    out_len = sizeof(sa_family_t);
    sa1_4.get_sa_by_family(reinterpret_cast<sockaddr *>(&out4_1), out_len, AF_INET);
    EXPECT_EQ(AF_INET, out4_1.sin_family);
    EXPECT_EQ(sizeof(sockaddr_in), out_len);
    out_len = sizeof(out4_1);
    sa1_4.get_sa_by_family(reinterpret_cast<sockaddr *>(&out4_1), out_len, AF_INET);
    sock_addr out4_1_addr(reinterpret_cast<const sockaddr *>(&out4_1), sizeof(out4_1));
    EXPECT_TRUE(out4_1_addr.to_str_ip_port(true) == "153.153.170.170:2304");
    EXPECT_EQ(sizeof(sockaddr_in), out_len);

    sock_addr sa1_6(out6_1_addr);
    out_len = 0U;
    sa1_6.get_sa_by_family(nullptr, out_len, AF_INET6);
    EXPECT_EQ(sizeof(sockaddr_in6), out_len);
    EXPECT_EQ(sizeof(sockaddr_in6), out_len);
    out_len = sizeof(sa_family_t);
    sa1_6.get_sa_by_family(reinterpret_cast<sockaddr *>(&out6_1), out_len, AF_INET6);
    EXPECT_EQ(AF_INET6, out6_1.sin6_family);
    EXPECT_EQ(sizeof(sockaddr_in6), out_len);
    out_len = sizeof(out6_1);
    sa1_6.get_sa_by_family(reinterpret_cast<sockaddr *>(&out6_1), out_len, AF_INET);
    sock_addr out6_2_addr(reinterpret_cast<const sockaddr *>(&out6_1), sizeof(out6_1));
    EXPECT_TRUE(out6_2_addr.to_str_ip_port(true) == "[::ffff:153.153.170.170]:2304");
    EXPECT_EQ(sizeof(sockaddr_in6), out_len);

    out6_2_addr.strip_mapped_ipv4();
    EXPECT_TRUE(out6_2_addr.to_str_ip_port(true) == "153.153.170.170:2304");
    out4_1_addr.strip_mapped_ipv4();
    EXPECT_TRUE(out4_1_addr.to_str_ip_port(true) == "153.153.170.170:2304");
}
