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

#ifndef XLIO_NVME_PARSE_INPUT_ARGS_H
#define XLIO_NVME_PARSE_INPUT_ARGS_H
#include <atomic>
#include <stdlib.h>
#include "proto/mem_desc.h"

class nvme_pdu_mdesc : public mem_desc {
public:
    nvme_pdu_mdesc(size_t num_segments, iovec *iov, xlio_pd_key *aux_data, uint32_t seqno,
                   size_t length, std::unique_ptr<uint8_t[]> &&container)
        : m_num_segments(num_segments)
        , m_iov(iov)
        , m_aux_data(aux_data)
        , m_seqno(seqno)
        , m_length(length)
        , m_curr_lkey_index(0U)
        , m_view({num_segments, 0U})
        , m_container(std::move(container))
        , m_ref(1) {};

    ~nvme_pdu_mdesc() override { m_container.reset(); }

    static inline nvme_pdu_mdesc *create(size_t num_segments, const iovec *iov,
                                         const xlio_pd_key *aux_data, uint32_t seqno, size_t length)
    {
        const auto offsetof_iov = sizeof(nvme_pdu_mdesc);
        auto offsetof_aux_data = sizeof(nvme_pdu_mdesc) + (num_segments * sizeof(iovec));
        static_assert(offsetof_iov % alignof(iovec) == 0U, "The offset of iov is not OK");
        assert(offsetof_aux_data % alignof(xlio_pd_key) == 0U);

        auto this_addr = reinterpret_cast<uint8_t *>(aligned_alloc(
            alignof(nvme_pdu_mdesc),
            num_segments * (sizeof(iovec) + sizeof(xlio_pd_key)) + sizeof(nvme_pdu_mdesc)));
        if (this_addr == nullptr) {
            return nullptr;
        }
        auto container = std::unique_ptr<uint8_t[]>(this_addr);
        auto iov_addr = reinterpret_cast<iovec *>(&this_addr[offsetof_iov]);
        auto aux_data_addr = reinterpret_cast<xlio_pd_key *>(&this_addr[offsetof_aux_data]);

        memcpy(iov_addr, iov, num_segments * sizeof(iovec));
        memcpy(aux_data_addr, aux_data, num_segments * sizeof(xlio_pd_key));

        return new (this_addr) nvme_pdu_mdesc(num_segments, iov_addr, aux_data_addr, seqno, length,
                                              std::move(container));
    }

    void get(void) override { m_ref.fetch_add(1, std::memory_order_relaxed); }

    void put(void) override
    {
        int ref = m_ref.fetch_sub(1, std::memory_order_relaxed);
        if (ref == 1) {
            this->~nvme_pdu_mdesc();
        }
    }

    static inline bool is_segment_in_range(const void *seg_addr, size_t seg_len, const iovec &range)
    {
        uintptr_t seg_start = reinterpret_cast<uintptr_t>(seg_addr);
        uintptr_t seg_end = seg_start + seg_len;

        uintptr_t range_start = reinterpret_cast<uintptr_t>(range.iov_base);
        uintptr_t range_end = range_start + range.iov_len;

        return range_start <= seg_start && seg_end <= range_end;
    }

    /* Optimization for the common path when we check lkey for the current or the following iov */
    inline uint32_t get_lkey(const void *addr, size_t len)
    {
        if (m_curr_lkey_index < m_num_segments &&
            is_segment_in_range(addr, len, m_iov[m_curr_lkey_index])) {
            return m_aux_data[m_curr_lkey_index].mkey;
        } else if ((++m_curr_lkey_index) < m_num_segments &&
                   is_segment_in_range(addr, len, m_iov[m_curr_lkey_index])) {
            return m_aux_data[m_curr_lkey_index].mkey;
        }

        auto itr = std::find_if(&m_iov[0U], &m_iov[m_num_segments], [&](const iovec &iov) {
            return is_segment_in_range(addr, len, iov);
        });

        if (itr == &m_iov[m_num_segments]) {
            return LKEY_TX_DEFAULT;
        }
        m_curr_lkey_index = std::distance(&m_iov[0U], itr);
        return m_aux_data[m_curr_lkey_index].mkey;
    }

    uint32_t get_lkey(mem_buf_desc_t *, ib_ctx_handler *, const void *addr, size_t len) override
    {
        return get_lkey(addr, len);
    }

    struct chunk {
        iovec iov;
        uint32_t mkey;
        chunk(void *base, size_t len, uint32_t key)
            : iov({base, len})
            , mkey(key) {};
        chunk()
            : chunk(nullptr, 0U, LKEY_TX_DEFAULT) {};
        inline bool is_valid()
        {
            return iov.iov_base != nullptr && iov.iov_len != 0U && mkey != LKEY_TX_DEFAULT;
        }
    };

    /* returns the distance in bytes from the begining of the PDU containing the given seqno and
     * resets the internal state to the appropriate iov. In case of failiure returns m_length */
    size_t reset(uint32_t seqno);
    chunk next_chunk(size_t length);

    size_t m_num_segments;
    iovec *m_iov;
    xlio_pd_key *m_aux_data;
    uint32_t m_seqno;
    size_t m_length;

private:
    size_t m_curr_lkey_index;
    struct view {
        size_t index;
        size_t offset;
    };
    view m_view;
    std::unique_ptr<uint8_t[]> m_container;
    std::atomic_int m_ref;
};

#endif /* XLIO_NVME_PARSE_INPUT_ARGS_H */
