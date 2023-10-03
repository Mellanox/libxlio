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

#ifndef _SOCKINFO_NVME_H
#define _SOCKINFO_NVME_H
#include <algorithm>
#include <memory>
#include <sys/uio.h>
#include "sockinfo_ulp.h" /* sockinfo_tcp_ops */
#include "dev/qp_mgr.h"
#include "proto/nvme_parse_input_args.h"
#include "xlio_extra.h"
#include "lwip/err.h" /* err_t */

typedef struct xlio_tx_call_attr xlio_tx_call_attr_t;
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
    ~sockinfo_tcp_ops_nvme()
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

    int m_nvme_feature_mask;

private:
    std::unique_ptr<xlio_tis> m_p_tis;
    nvme_pdu_mdesc *m_pdu_mdesc;
    uint32_t m_expected_seqno;
    bool m_is_tx_offload;
    bool m_is_ddgs_on;

    int setsockopt_tx(const uint32_t &config);
};

#endif /* _SOCKINFO_NVME_H */
