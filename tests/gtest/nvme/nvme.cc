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

#include <array>
#include <functional>
#include <future>
#include "common/def.h"
#include "common/base.h"
#include "dev/qp_mgr_eth_mlx5.h"
#include "proto/nvme_parse_input_args.h"
#include "tcp/tcp_base.h"
#include "xlio_extra.h"
#include <sys/uio.h>

using namespace std;

/**
 * Test NVMe request processing
 */
class nvme_new_request : public testing::Test {
protected:
    nvme_new_request()
        : arr()
        , aux_data({[0] = {.message_length = sizeof(arr[0]) + sizeof(arr[1]), .mkey = 123},
                    [1] = {.message_length = 0, .mkey = 456},
                    [2] = {.message_length = sizeof(arr[2]), .mkey = 789}})
        , aux_data_current(&aux_data[0])
        , aux_data_end(&aux_data[0] + iovec_sz)
        , iov({
              [0] = {.iov_base = const_cast<void *>(static_cast<const void *>(&arr[0][0])),
                     .iov_len = sizeof(arr[0])},
              [1] = {.iov_base = const_cast<void *>(static_cast<const void *>(&arr[1][0])),
                     .iov_len = sizeof(arr[1])},
              [2] = {.iov_base = const_cast<void *>(static_cast<const void *>(&arr[2][0])),
                     .iov_len = sizeof(arr[2])},
          }) {};
    static const constexpr size_t iovec_sz {3U};

    const uint8_t arr[iovec_sz][8];
    xlio_pd_key aux_data[iovec_sz];
    const xlio_pd_key *aux_data_current, *aux_data_end;
    const iovec iov[iovec_sz];
};

const constexpr size_t nvme_new_request::iovec_sz;

/**
 * @test nvme_new_request.is_new_nvme_pdu_with_zero_size
 * @brief
 *    Test conditions for what appears as the start of a new NVMe PDU
 * @details
 */
TEST_F(nvme_new_request, is_new_nvme_pdu_with_zero_size)
{
    ASSERT_FALSE(is_new_nvme_pdu(&aux_data[0], 0U));
}

/**
 * @test nvme_new_request.is_new_nvme_pdu_with_nullptr_aux_data_pointer
 * @brief
 *    Test conditions for what appears as the start of a new NVMe PDU
 * @details
 */
TEST_F(nvme_new_request, is_new_nvme_pdu_with_nullptr_aux_data_pointer)
{
    ASSERT_FALSE(is_new_nvme_pdu(nullptr, iovec_sz));
}

/**
 * @test nvme_new_request.is_new_nvme_pdu_with_zero_message_size
 * @brief
 *    Test conditions for what appears as the start of a new NVMe PDU
 * @details
 */
TEST_F(nvme_new_request, is_new_nvme_pdu_with_zero_message_size)
{
    xlio_pd_key aux {.message_length = 0U, .mkey = 123U};
    ASSERT_FALSE(is_new_nvme_pdu(&aux, 1U));
}

/**
 * @test nvme_new_request.is_new_nvme_pdu_without_valid_mkey
 * @brief
 *    Test conditions for what appears as the start of a new NVMe PDU
 * @details
 */
TEST_F(nvme_new_request, is_new_nvme_pdu_without_valid_mkey)
{
    xlio_pd_key aux {.message_length = 8U, .mkey = 0U};
    ASSERT_FALSE(is_new_nvme_pdu(&aux, 1U));
}

/**
 * @test nvme_new_request.is_new_nvme_pdu_with_valid_arguments
 * @brief
 *    Test conditions for what appears as the start of a new NVMe PDU
 * @details
 */
TEST_F(nvme_new_request, is_new_nvme_pdu_with_valid_arguments)
{
    ASSERT_TRUE(is_new_nvme_pdu(&aux_data[0], iovec_sz));
}

/**
 * @test nvme_new_request.from_batch_fails_with_nullptr_iov
 * @brief
 *    Check the proper nvmeotcp_tx construction
 * @details
 */
TEST_F(nvme_new_request, from_batch_fails_with_nullptr_iov)
{
    auto nvme = nvmeotcp_tx(nullptr, aux_data_current, iovec_sz);
    ASSERT_FALSE(nvme.is_valid()) << "NVMEoTCP_TX should be invalid with nullptr iov";
}

/**
 * @test nvme_new_request.from_batch_fails_with_nullptr_aux_data
 * @brief
 *    Check the proper nvmeotcp_tx construction
 * @details
 */
TEST_F(nvme_new_request, from_batch_fails_with_nullptr_aux_data)
{
    auto nvme = nvmeotcp_tx(iov, nullptr, iovec_sz);
    ASSERT_FALSE(nvme.is_valid()) << "NVMEoTCP_TX should be invalid with nullptr aux_data";
}

/**
 * @test nvme_new_request.from_batch_fails_with_zero_iov_num
 * @brief
 *    Check the proper nvmeotcp_tx construction
 * @details
 */
TEST_F(nvme_new_request, from_batch_fails_with_zero_iov_num)
{
    auto nvme = nvmeotcp_tx(iov, aux_data_current, 0U);
    ASSERT_FALSE(nvme.is_valid()) << "NVMEoTCP_TX should be invalid with zero iov_num";
}

/**
 * @test nvme_new_request.from_batch_correctly_initialized
 * @brief
 *    Check the proper nvmeotcp_tx construction
 * @details
 */
TEST_F(nvme_new_request, from_batch_correctly_initialized)
{
    auto nvme = nvmeotcp_tx(iov, aux_data_current, iovec_sz);
    ASSERT_TRUE(nvme.is_valid()) << "NVMEoTCP_TX should be valid";
}

/**
 * @test nvme_new_request.get_next_pdu_fails_with_invalid_nvme
 * @brief
 *    Check the proper nvmeotcp_tx construction
 * @details
 */
TEST_F(nvme_new_request, get_next_pdu_fails_with_invalid_nvme)
{
    auto nvme = nvmeotcp_tx(iov, aux_data_current, 0U);
    auto pdu = nvme.get_next_pdu(1U);

    ASSERT_EQ(nullptr, pdu) << "Invalid nvmeotcp_tx should produce invalid pdu";
}

/**
 * @test nvme_new_request.get_next_pdu_succeeds
 * @brief
 *    Check the proper nvmeotcp_tx construction
 * @details
 */
TEST_F(nvme_new_request, get_next_pdu_succeeds)
{
    auto nvme = nvmeotcp_tx(iov, aux_data_current, iovec_sz);
    auto pdu = nvme.get_next_pdu(1U);

    ASSERT_NE(nullptr, pdu);
    ASSERT_TRUE(pdu->is_valid());
    ASSERT_EQ(2U, pdu->m_iov_num);
    ASSERT_EQ(sizeof(arr[0]), pdu->m_iov[0].iov_len);
    ASSERT_EQ(&arr[0], pdu->m_iov[0].iov_base);
    ASSERT_EQ(16U, pdu->m_aux_data[0].message_length);
    ASSERT_EQ(aux_data[0].mkey, pdu->m_aux_data[0].mkey);
    ASSERT_EQ(sizeof(arr[1]), pdu->m_iov[1].iov_len);
    ASSERT_EQ(&arr[1], pdu->m_iov[1].iov_base);
    ASSERT_EQ(0U, pdu->m_aux_data[1].message_length);
    ASSERT_EQ(aux_data[1].mkey, pdu->m_aux_data[1].mkey);

    pdu = nvme.get_next_pdu(2U);
    ASSERT_EQ(1U, pdu->m_iov_num);
    ASSERT_NE(nullptr, pdu);
    ASSERT_TRUE(pdu->is_valid());
    ASSERT_EQ(sizeof(arr[2]), pdu->m_iov[0].iov_len);
    ASSERT_EQ(&arr[2], pdu->m_iov[0].iov_base);
    ASSERT_EQ(8U, pdu->m_aux_data[0].message_length);
    ASSERT_EQ(aux_data[2].mkey, pdu->m_aux_data[0].mkey);

    pdu = nvme.get_next_pdu(3U);
    ASSERT_EQ(nullptr, pdu);
}

/**
 * @test nvme_new_request.get_next_pdu_succeeds
 * @brief
 *    Check correct segmentation of the iovec pdu
 * @details
 */
TEST_F(nvme_new_request, pdu_get_segment)
{
    auto nvme = nvmeotcp_tx(iov, aux_data_current, iovec_sz);
    auto pdu = nvme.get_next_pdu(1U);

    ASSERT_NE(nullptr, pdu);
    EXPECT_TRUE((pdu->is_valid())) << "The pdu should be valid";
    iovec out_iov[64U] = {{nullptr, 0}};
    xlio_pd_key out_aux_data[64U] = {{0, 0}};

    auto num_iovs_in_segment = pdu->get_segment(6U, out_iov, out_aux_data, 64U);
    ASSERT_EQ(1U, num_iovs_in_segment) << "The pdu contains 16, 6 should be available";
    num_iovs_in_segment = pdu->get_segment(10U, out_iov, out_aux_data, 64U);
    ASSERT_EQ(2U, num_iovs_in_segment) << "The pdu contains 10, 10 should be available";
    num_iovs_in_segment = pdu->get_segment(100U, out_iov, out_aux_data, 64U);
    ASSERT_EQ(0U, num_iovs_in_segment) << "The pdu contains 0";

    pdu = nvme.get_next_pdu(17U);
    ASSERT_NE(nullptr, pdu);
    EXPECT_TRUE((pdu->is_valid())) << "The pdu should be valid";
    num_iovs_in_segment = pdu->get_segment(666U, out_iov, out_aux_data, 64U);
    ASSERT_EQ(1U, num_iovs_in_segment) << "The pdu contains 8";
}

class nvme_pdu_mdesc_test_suite : public nvme_new_request {
protected:
    nvme_pdu_mdesc_test_suite()
        : pdu_mdesc(nvmeotcp_tx(iov, aux_data_current, iovec_sz).get_next_pdu(1U)) {};
    ~nvme_pdu_mdesc_test_suite() = default;
    nvme_pdu_mdesc pdu_mdesc;
};

/**
 * @test nvme_pdu_mdesc_test_suite.nvme_pdu_mdesc_get_lkey_before_range_fails
 * @brief
 *    Check correct segmentation of the iovec pdu
 * @details
 */
TEST_F(nvme_pdu_mdesc_test_suite, nvme_pdu_mdesc_get_lkey_before_range_fails)
{
    auto addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[0][0]) - 1U);
    ASSERT_EQ(LKEY_USE_DEFAULT, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 1U));
}

/**
 * @test nvme_pdu_mdesc_test_suite.nvme_pdu_mdesc_get_lkey_after_range_fails
 * @brief
 *    Check correct segmentation of the iovec pdu
 * @details
 */
TEST_F(nvme_pdu_mdesc_test_suite, nvme_pdu_mdesc_get_lkey_after_range_fails)
{
    auto addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[1][7]) + 1U);
    ASSERT_EQ(LKEY_USE_DEFAULT, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 1U));
}

/**
 * @test nvme_pdu_mdesc_test_suite.nvme_pdu_mdesc_get_lkey_addr_overlaps_start_of_range_fails
 * @brief
 *    Check correct segmentation of the iovec pdu
 * @details
 */
TEST_F(nvme_pdu_mdesc_test_suite, nvme_pdu_mdesc_get_lkey_addr_overlaps_start_of_range_fails)
{
    auto addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[0][0]) - 1U);
    ASSERT_EQ(LKEY_USE_DEFAULT, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 4U));
}

/**
 * @test nvme_pdu_mdesc_test_suite.nvme_pdu_mdesc_get_lkey_addr_overlaps_end_of_range_fails
 * @brief
 *    Check correct segmentation of the iovec pdu
 * @details
 */
TEST_F(nvme_pdu_mdesc_test_suite, nvme_pdu_mdesc_get_lkey_addr_overlaps_end_of_range_fails)
{
    auto addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[0][6]));
    ASSERT_EQ(LKEY_USE_DEFAULT, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 4U));
}

/**
 * @test nvme_pdu_mdesc_test_suite.nvme_pdu_mdesc_get_lkey_full_match_succeeds
 * @brief
 *    Check correct segmentation of the iovec pdu
 * @details
 */
TEST_F(nvme_pdu_mdesc_test_suite, nvme_pdu_mdesc_get_lkey_full_match_succeeds)
{
    auto addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[0][0]));
    ASSERT_EQ(aux_data[0].mkey, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 8U));

    addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[1][0]));
    ASSERT_EQ(aux_data[1].mkey, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 8U));
}

/**
 * @test nvme_pdu_mdesc_test_suite.nvme_pdu_mdesc_get_lkey_partial_match_succeeds
 * @brief
 *    Check correct segmentation of the iovec pdu
 * @details
 */
TEST_F(nvme_pdu_mdesc_test_suite, nvme_pdu_mdesc_get_lkey_partial_match_succeeds)
{
    auto addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[0][1]));
    ASSERT_EQ(aux_data[0].mkey, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 7U));

    addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[0][0]));
    ASSERT_EQ(aux_data[0].mkey, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 7U));

    addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[0][1]));
    ASSERT_EQ(aux_data[0].mkey, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 6U));

    addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[1][1]));
    ASSERT_EQ(aux_data[1].mkey, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 7U));

    addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[1][0]));
    ASSERT_EQ(aux_data[1].mkey, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 7U));

    addr = reinterpret_cast<const void *>(reinterpret_cast<uintptr_t>(&arr[1][1]));
    ASSERT_EQ(aux_data[1].mkey, pdu_mdesc.get_lkey(nullptr, nullptr, addr, 6U));
}

class xlio_ti_test : public testing::Test {
};

/**
 * @test xlio_ti_test.default_constructor
 * @brief
 *    Check xlio_ti class
 * @details
 */
TEST_F(xlio_ti_test, default_constructor)
{
    auto ti = xlio_ti();
    ASSERT_EQ(XLIO_TI_UNKNOWN, ti.m_type);
    ASSERT_FALSE(ti.m_released);
    ASSERT_EQ(0U, ti.m_ref);
    ASSERT_EQ(nullptr, ti.m_callback);
    ASSERT_EQ(nullptr, ti.m_callback_arg);
}

class nvme_setsockopt : public tcp_base {
protected:
    void SetUp() override
    {
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        /* Setup server */
        server_socket = sock_create();
        ASSERT_EQ(0, setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));
        ASSERT_EQ(0, bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)));
        ASSERT_EQ(0, listen(server_socket, 1024));

        /* Setup client */
        client_socket = sock_create();
        ASSERT_EQ(0, setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)));
        ASSERT_TRUE(server_socket && client_socket);

        /* Asynchronously establish connection */
        std::future<bool> server_task = std::async(
            std::launch::async, [&]() { return 0 < accept(server_socket, nullptr, nullptr); });
        std::future<bool> client_task = std::async(std::launch::async, [&]() {
            return 0 ==
                connect(client_socket, reinterpret_cast<const sockaddr *>(&server_addr),
                        sizeof(server_addr));
        });

        using namespace std::chrono_literals;
        if (server_task.wait_for(3s) != std::future_status::ready || !server_task.get() ||
            client_task.wait_for(3s) != std::future_status::ready || !client_task.get()) {
            GTEST_SKIP();
        }
    }
    void TearDown() override
    {
        close(server_socket);
        close(client_socket);
    }

    int server_socket = -1;
    int client_socket = -1;
};

TEST_F(nvme_setsockopt, set_ulp_nvme)
{
    const std::string option = "nvme";
    int result = setsockopt(client_socket, IPPROTO_TCP, TCP_ULP, option.c_str(), option.length());

    if (result == 0) {
        int optval = 42;
        int ret = setsockopt(client_socket, NVDA_NVME, NVME_TX, &optval, sizeof(optval));
        ASSERT_EQ(0, ret) << "NVME_TX is unsupported";
    }
}
