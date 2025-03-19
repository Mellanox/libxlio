/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _SOCKINFO_NVME_H
#define _SOCKINFO_NVME_H
#include <algorithm>
#include <memory>
#include <sys/uio.h>
#include "sockinfo_ulp.h" /* sockinfo_tcp_ops */
#include "dev/hw_queue_tx.h"
#include "proto/nvme_parse_input_args.h"
#include "xlio_extra.h"
#include "lwip/err.h" /* err_t */

struct xlio_send_attr;

class sockinfo_tcp_ops_nvme : public sockinfo_tcp_ops {
public:
    sockinfo_tcp_ops_nvme(sockinfo_tcp *sock, int nvme_feature_mask)
        : sockinfo_tcp_ops(sock)
        , m_nvme_feature_mask(nvme_feature_mask)
        , m_p_tis(nullptr)
        , m_pdu_mdesc(nullptr)
        , m_expected_seqno(0U)
        , m_is_tx_offload(false)
        , m_is_ddgs_on(false)
    {
    }
    ~sockinfo_tcp_ops_nvme() override
    {
        if (m_pdu_mdesc) {
            m_pdu_mdesc->put();
        }
    }

    int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen) override;
    ssize_t tx(xlio_tx_call_attr_t &tx_arg) override;
    int postrouting(struct pbuf *p, struct tcp_seg *seg, xlio_send_attr &attr) override;
    bool handle_send_ret(ssize_t ret, struct tcp_seg *seg) override;
    err_t recv(struct pbuf *p) override;

private:
    int setsockopt_tx(const uint32_t &config);

public:
    int m_nvme_feature_mask;

private:
    std::unique_ptr<xlio_tis> m_p_tis;
    nvme_pdu_mdesc *m_pdu_mdesc;
    uint32_t m_expected_seqno;
    bool m_is_tx_offload;
    bool m_is_ddgs_on;
};

#endif /* _SOCKINFO_NVME_H */
