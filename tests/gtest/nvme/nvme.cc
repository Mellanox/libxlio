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

    auto segment = pdu->get_first_segment(6U, out_iov, 64U);
    ASSERT_EQ(1U, segment.iov_num) << "Wrong number of segments";
    ASSERT_EQ(6U, segment.length) << "The actual bytes calculation is wrong";
    ASSERT_EQ(6U, out_iov[0].iov_len) << "iov_len is incorrect";
    pdu->consume(segment.length);

    segment = pdu->get_segment(11U, out_iov, 64U);
    ASSERT_EQ(2U, segment.iov_num) << "Wrong number of segments";
    ASSERT_EQ(10U, segment.length) << "The actual bytes calculation is wrong";
    ASSERT_EQ(2U, out_iov[0].iov_len) << "iov_len is incorrect";
    ASSERT_EQ(8U, out_iov[1].iov_len) << "iov_len is incorrect";
    pdu->consume(segment.length);

    segment = pdu->get_segment(100U, out_iov, 64U);
    ASSERT_EQ(0U, segment.iov_num) << "Wrong number of segments";
    ASSERT_EQ(0U, segment.length) << "The actual bytes calculation is wrong";
    pdu->consume(segment.length);

    segment = pdu->get_first_segment(666U, out_iov, 64U);
    ASSERT_EQ(2U, segment.iov_num) << "Wrong number of segments";
    ASSERT_EQ(16U, segment.length) << "The actual bytes calculation is wrong";
    ASSERT_EQ(8U, out_iov[0].iov_len) << "iov_len is incorrect";
    pdu->consume(segment.length);

    pdu = nvme.get_next_pdu(17U);
    ASSERT_NE(nullptr, pdu);
    EXPECT_TRUE(pdu->is_valid()) << "The PDU should be valid";
    segment = pdu->get_segment(666U, out_iov, 64U);
    ASSERT_EQ(1U, segment.iov_num) << "Wrong number of segments";
    ASSERT_EQ(8U, segment.length) << "The actual bytes calculation is wrong";
    ASSERT_EQ(8U, out_iov[0].iov_len) << "iov_len is incorrect";
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

static const uint8_t input_pdu_without_ddgst[] = {
    0x04, 0x02, 0x48, 0x48, 0x4c, 0x04, 0x00, 0x00, 0x7f, 0x40, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd5, 0x3c, 0x37, 0x98, 0xe8, 0xd3, 0x49, 0x37,
    0x9e, 0xb3, 0x4c, 0x4e, 0x1e, 0x67, 0x52, 0x44, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6e, 0x71, 0x6e, 0x2e, 0x32, 0x30, 0x31, 0x36,
    0x2d, 0x30, 0x36, 0x2e, 0x69, 0x6f, 0x2e, 0x6e, 0x76, 0x6d, 0x65, 0x74, 0x2e, 0x74, 0x65, 0x73,
    0x74, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x30, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6e, 0x71, 0x6e, 0x2e, 0x32, 0x30, 0x31, 0x34,
    0x2d, 0x30, 0x38, 0x2e, 0x6f, 0x72, 0x67, 0x2e, 0x6e, 0x76, 0x6d, 0x65, 0x78, 0x70, 0x72, 0x65,
    0x73, 0x73, 0x3a, 0x75, 0x75, 0x69, 0x64, 0x3a, 0x64, 0x35, 0x33, 0x63, 0x33, 0x37, 0x39, 0x38,
    0x2d, 0x65, 0x38, 0x64, 0x33, 0x2d, 0x34, 0x39, 0x33, 0x37, 0x2d, 0x39, 0x65, 0x62, 0x33, 0x2d,
    0x34, 0x63, 0x34, 0x65, 0x31, 0x65, 0x36, 0x37, 0x35, 0x32, 0x34, 0x34, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const size_t input_pdu_without_ddgst_length = 1100U;

class nvme_tx : public tcp_send_zc {
protected:
    void SetUp() override
    {
#ifndef DEFINED_DPCP
        GTEST_SKIP();
#endif /* DEFINED_DPCP */
        int test_buf_size = 0;
        m_test_buf = reinterpret_cast<char *>(
            create_tmp_buffer(input_pdu_without_ddgst_length, &test_buf_size));

        ASSERT_NE(nullptr, m_test_buf) << "Valid test buffer reguired";
        ASSERT_GE(test_buf_size, 0) << "Need larger test data buffer";
        ASSERT_GE(static_cast<size_t>(test_buf_size), input_pdu_without_ddgst_length)
            << "Need larger test data buffer";
        memcpy(m_test_buf, input_pdu_without_ddgst, input_pdu_without_ddgst_length);
    }

    void client_process()
    {
        auto client_fd = tcp_base::sock_create();
        ASSERT_GE(client_fd, 0) << "Unable to open the client socket";

        auto rc = bind(client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
        ASSERT_EQ(0, rc) << "Unable to bind to address "
                         << sys_addr2str((struct sockaddr *)&client_addr);

        barrier_fork();
        rc = connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc) << "Unable to connect to address "
                         << sys_addr2str((struct sockaddr *)&server_addr);

        /* ------------------NVME/TCP offset setup--------------------------- */
        const std::string option = "nvme";
        rc = setsockopt(client_fd, IPPROTO_TCP, TCP_ULP, option.c_str(), option.length());
        ASSERT_EQ(0, rc) << "NVME is unsupported";

        uint32_t configure = XLIO_NVME_DDGST_ENABLE | XLIO_NVME_DDGST_OFFLOAD | 0U /* pda */;
        rc = setsockopt(client_fd, NVDA_NVME, NVME_TX, &configure, sizeof(configure));
        ASSERT_EQ(0, rc) << "NVME_TX is unsupported";

        int opt_val = 1;
        rc = setsockopt(client_fd, SOL_SOCKET, SO_ZEROCOPY, &opt_val, sizeof(opt_val));
        ASSERT_EQ(0, rc);
        /* ------------------Memory registration----------------------------- */
        struct xlio_pd_attr pd_attr;
        auto pd_attr_in_out_len = static_cast<socklen_t>(sizeof(pd_attr));
        rc = getsockopt(client_fd, SOL_SOCKET, SO_XLIO_PD, &pd_attr, &pd_attr_in_out_len);
        ASSERT_EQ(0, rc);
        ASSERT_EQ(sizeof(pd_attr), pd_attr_in_out_len);
        ASSERT_NE(nullptr, pd_attr.ib_pd);

        auto registered_mr = ibv_reg_mr(reinterpret_cast<ibv_pd *>(pd_attr.ib_pd), m_test_buf,
                                        input_pdu_without_ddgst_length, IBV_ACCESS_LOCAL_WRITE);

        /* ------------------Sendmsg parameter preparation------------------- */
        xlio_pd_key pd_key[1] = {
            [0] = {.message_length = input_pdu_without_ddgst_length, .mkey = registered_mr->lkey}};
        size_t pd_key_len = sizeof(pd_key);
        iovec iov[1] = {[0] = {.iov_base = m_test_buf, .iov_len = input_pdu_without_ddgst_length}};
        alignas(cmsghdr) uint8_t cmsg_buf[CMSG_SPACE(pd_key_len)] = {0U};
        msghdr msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = &iov[0],
            .msg_iovlen = 1,
            .msg_control = &cmsg_buf[0U],
            .msg_controllen = CMSG_LEN(pd_key_len),
            .msg_flags = 0,
        };
        cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_XLIO_NVME_PD;
        cmsg->cmsg_len = msg.msg_controllen;
        memcpy(CMSG_DATA(cmsg), pd_key, pd_key_len);

        rc = sendmsg(client_fd, &msg, MSG_DONTWAIT | MSG_ZEROCOPY);
        ASSERT_EQ(static_cast<int>(input_pdu_without_ddgst_length), rc);

        struct epoll_event event;
        event.events = EPOLLOUT;
        event.data.fd = client_fd;
        rc = test_base::event_wait(&event);
        EXPECT_GE(rc, 0);
        ASSERT_TRUE(EPOLLOUT & event.events);

        uint32_t lo, hi;
        rc = do_recv_expected_completion(client_fd, lo, hi, 1);
        EXPECT_GE(rc, 0);

        peer_wait(client_fd);

        close(client_fd);
        ibv_dereg_mr(registered_mr);
    }

    void server_process(int child_pid)
    {
        int listen_fd;
        struct sockaddr peer_addr;
        socklen_t socklen;
        char buf[input_pdu_without_ddgst_length + 10];

        listen_fd = tcp_base::sock_create();
        ASSERT_LE(0, listen_fd);

        auto rc = bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        ASSERT_EQ(0, rc) << "Unable to bind to address "
                         << sys_addr2str((struct sockaddr *)&server_addr);

        rc = listen(listen_fd, 5);
        ASSERT_EQ(0, rc) << "Unable to listen";

        barrier_fork(child_pid);

        socklen = sizeof(peer_addr);
        auto server_fd = accept(listen_fd, &peer_addr, &socklen);
        ASSERT_LE(0, server_fd);

        size_t data_received = 0;
        rc = 0;
        do {
            rc = recv(server_fd, (void *)&buf[data_received], sizeof(buf) - data_received, 0);
        } while (rc >= 0 &&
                 (data_received += static_cast<size_t>(rc)) < input_pdu_without_ddgst_length);

        cerr << "received " << data_received << endl;
        ASSERT_GE(data_received, input_pdu_without_ddgst_length);

        ASSERT_EQ(0, memcmp(buf, m_test_buf, input_pdu_without_ddgst_length));

        close(server_fd);
        close(listen_fd);

        ASSERT_EQ(0, wait_fork(child_pid));
    }
};

TEST_F(nvme_tx, please_fail)
{
    int pid = fork();

    if (0 == pid) { /* I am the child */
        client_process();
        exit(testing::Test::HasFailure());
    } else {
        server_process(pid);
    }
}
