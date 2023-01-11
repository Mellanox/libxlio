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
 * SOCK Base class for tests
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
 * @test nvme_new_request.NVME_from_batch_fails_with_nullptr_iov
 * @brief
 *    Check the proper NVMEoTCP_TX construction
 * @details
 */
TEST_F(nvme_new_request, NVME_from_batch_fails_with_nullptr_iov)
{
    auto nvme = NVMEoTCP_TX::from_batch(nullptr, aux_data_current, iovec_sz);
    ASSERT_FALSE(*nvme) << "NVMEoTCP_TX should be invalid with nullptr iov";
}

/**
 * @test nvme_new_request.NVME_from_batch_fails_with_nullptr_aux_data
 * @brief
 *    Check the proper NVMEoTCP_TX construction
 * @details
 */
TEST_F(nvme_new_request, NVME_from_batch_fails_with_nullptr_aux_data)
{
    auto nvme = NVMEoTCP_TX::from_batch(iov, nullptr, iovec_sz);
    ASSERT_FALSE(*nvme) << "NVMEoTCP_TX should be invalid with nullptr aux_data";
}

/**
 * @test nvme_new_request.NVME_from_batch_fails_with_zero_iov_num
 * @brief
 *    Check the proper NVMEoTCP_TX construction
 * @details
 */
TEST_F(nvme_new_request, NVME_from_batch_fails_with_zero_iov_num)
{
    auto nvme = NVMEoTCP_TX::from_batch(iov, aux_data_current, 0U);
    ASSERT_FALSE(*nvme) << "NVMEoTCP_TX should be invalid with zero iov_num";
}

/**
 * @test nvme_new_request.NVME_from_batch_correctly_initialized
 * @brief
 *    Check the proper NVMEoTCP_TX construction
 * @details
 */
TEST_F(nvme_new_request, NVME_from_batch_correctly_initialized)
{
    auto nvme = NVMEoTCP_TX::from_batch(iov, aux_data_current, iovec_sz);
    ASSERT_TRUE(*nvme) << "NVMEoTCP_TX should be valid";
}

/**
 * @test nvme_new_request.NVME_get_next_iovec_view_fails_with_invalid_nvme
 * @brief
 *    Check the proper NVMEoTCP_TX construction
 * @details
 */
TEST_F(nvme_new_request, NVME_get_next_iovec_view_fails_with_invalid_nvme)
{
    auto nvme = NVMEoTCP_TX::from_batch(iov, aux_data_current, 0U);
    auto view = nvme->get_next_iovec_view();

    ASSERT_FALSE(view) << "Invalid NVMEoTCP_TX should produce invalid view";
}

/**
 * @test nvme_new_request.NVME_get_next_iovec_view_succeeds
 * @brief
 *    Check the proper NVMEoTCP_TX construction
 * @details
 */
TEST_F(nvme_new_request, NVME_get_next_iovec_view_succeeds)
{
    auto nvme = NVMEoTCP_TX::from_batch(iov, aux_data_current, iovec_sz);
    auto view = nvme->get_next_iovec_view();

    ASSERT_EQ(2U, view.m_iov_num);
    ASSERT_TRUE(view);
    ASSERT_EQ(sizeof(arr[0]), view.m_iov[0].iov_len);
    ASSERT_EQ(&arr[0], view.m_iov[0].iov_base);
    ASSERT_EQ(sizeof(arr[1]), view.m_iov[1].iov_len);
    ASSERT_EQ(&arr[1], view.m_iov[1].iov_base);
    ASSERT_EQ(16U, view.m_aux_data[0].message_length);
    ASSERT_EQ(0U, view.m_aux_data[1].message_length);
    ASSERT_EQ(aux_data[0].mkey, view.m_aux_data[0].mkey);
    ASSERT_EQ(aux_data[1].mkey, view.m_aux_data[1].mkey);

    view = nvme->get_next_iovec_view();
    ASSERT_EQ(1U, view.m_iov_num);
    ASSERT_TRUE(view);
    ASSERT_EQ(sizeof(arr[2]), view.m_iov[0].iov_len);
    ASSERT_EQ(&arr[2], view.m_iov[0].iov_base);
    ASSERT_EQ(8U, view.m_aux_data[0].message_length);
    ASSERT_EQ(aux_data[2].mkey, view.m_aux_data[0].mkey);
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

class tcp_set_get_sockopt_connected : public tcp_base {
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

TEST_F(tcp_set_get_sockopt_connected, set_ulp_nvme)
{
    const std::string option = "nvme";
    int result = setsockopt(client_socket, IPPROTO_TCP, TCP_ULP, option.c_str(), option.length());

    if (result == 0) {
        int optval = 42;
        int ret = setsockopt(client_socket, SOL_NVME, NVME_TX, &optval, sizeof(optval));
        ASSERT_EQ(0, ret) << "NVME_TX is unsupported";
    }
}
