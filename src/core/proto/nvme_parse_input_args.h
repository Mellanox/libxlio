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
#include "proto/mem_desc.h"

static inline bool is_valid_aux_data_array(const xlio_pd_key *aux, size_t aux_data_sz)
{
    return aux != nullptr && aux_data_sz > 0;
}

static inline bool is_new_nvme_pdu(const xlio_pd_key *aux, size_t aux_data_sz)
{
    return is_valid_aux_data_array(aux, aux_data_sz) && aux->message_length > 0 && aux->mkey != 0U;
}

struct nvmeotcp_tx {

    nvmeotcp_tx() = default;
    inline bool is_valid() const
    {
        return m_iov != nullptr && m_aux_data != nullptr && m_iov_num != 0U;
    }

    struct pdu;
    std::unique_ptr<pdu> get_next_pdu(uint32_t seqnum)
    {
        if (!is_valid()) {
            return nullptr;
        }

        /* Roll to the start of the next DPU */
        while (m_current_pdu_iov_index < 64U &&
               m_aux_data[m_current_pdu_iov_index].message_length == 0U) {
            ++m_current_pdu_iov_index;
        }

        /* The iovec batches may contain multiple NVME PDUs. Each PDU may span multiple complete
         * iovec segments. */
        size_t remaining_pdu_length = m_aux_data[m_current_pdu_iov_index].message_length;
        size_t current_index = m_current_pdu_iov_index;

        while (remaining_pdu_length != 0U && remaining_pdu_length >= m_iov[current_index].iov_len) {
            remaining_pdu_length -= m_iov[current_index].iov_len;
            current_index++;
        }

        if (current_index <= m_iov_num && remaining_pdu_length == 0) {
            auto _pdu = std::make_unique<pdu>(&m_iov[m_current_pdu_iov_index],
                                              &m_aux_data[m_current_pdu_iov_index],
                                              current_index - m_current_pdu_iov_index, seqnum);
            m_current_pdu_iov_index = current_index;
            return _pdu;
        }
        return nullptr;
    }

    struct pdu {
        pdu(const iovec *iov, const xlio_pd_key *aux_data, size_t num, uint32_t seqnum)
            : m_iov()
            , m_aux_data()
            , m_iov_num(num)
            , m_curr_iov_index(0U)
            , m_curr_iov_offset(0U)
            , m_seqnum(seqnum)
        {
            if (iov != nullptr && aux_data != nullptr && num <= 64U) {
                memcpy(&m_iov[0U], iov, m_iov_num * sizeof(*iov));
                memcpy(&m_aux_data[0U], aux_data, m_iov_num * sizeof(iovec));
            } else {
                m_iov_num = 0U;
            }
        };

        inline size_t length() const { return m_aux_data[0].message_length; };

        struct segment {
            size_t iov_num, length;
            segment() = default;
            inline bool is_valid() const { return iov_num != 0U && length != 0U; }
        };

        /* Return value first is the number of iov elements second is the actual number of bytes in
         * iov */
        segment get_segment(size_t num_bytes, iovec *iov, size_t iov_num) const
        {
            if (num_bytes == 0U || iov == nullptr || iov_num == 0U || m_curr_iov_index >= 64U) {
                return {0U, 0U};
            }

            size_t out_iov_idx = 0U;
            size_t remaining_num_bytes = num_bytes;
            size_t curr_iov_index = m_curr_iov_index;
            size_t curr_iov_offset = m_curr_iov_offset;
            while (remaining_num_bytes != 0U && curr_iov_index < m_iov_num &&
                   out_iov_idx < iov_num) {
                iov[out_iov_idx].iov_base =
                    reinterpret_cast<uint8_t *>(m_iov[curr_iov_index].iov_base) + curr_iov_offset;
                if (m_iov[curr_iov_index].iov_len == 0U ||
                    m_iov[curr_iov_index].iov_base == nullptr) {
                    curr_iov_index++;
                    continue;
                }
                size_t bytes_in_curr_iov = m_iov[curr_iov_index].iov_len - curr_iov_offset;

                if (bytes_in_curr_iov > remaining_num_bytes) {
                    curr_iov_offset += remaining_num_bytes;
                    iov[out_iov_idx].iov_len = remaining_num_bytes;
                } else {
                    curr_iov_offset = 0U;
                    curr_iov_index++;
                    iov[out_iov_idx].iov_len = bytes_in_curr_iov;
                }
                remaining_num_bytes -= iov[out_iov_idx].iov_len;
                out_iov_idx += (bytes_in_curr_iov > 0U);
            }

            /* Optimization - zero only unfilled iovecs */
            memset(&iov[out_iov_idx], 0, sizeof(iovec) * (iov_num - out_iov_idx));
            return {out_iov_idx, num_bytes - remaining_num_bytes};
        }

        void consume(size_t num_bytes)
        {
            while (m_curr_iov_index < m_iov_num && num_bytes != 0U) {
                size_t bytes_in_curr_iov = m_iov[m_curr_iov_index].iov_len - m_curr_iov_offset;
                if (bytes_in_curr_iov <= num_bytes) {
                    m_curr_iov_offset = 0;
                    m_curr_iov_index++;
                    num_bytes -= bytes_in_curr_iov;
                } else {
                    m_curr_iov_offset += num_bytes;
                    break;
                }
            }
        }

        inline void reset()
        {
            m_curr_iov_index = 0U;
            m_curr_iov_offset = 0U;
        }

        inline segment get_first_segment(size_t num_bytes, iovec *iov, size_t iov_num)
        {
            reset();
            return get_segment(num_bytes, iov, iov_num);
        }

        inline iovec current_iov()
        {
            if (!is_valid() || m_curr_iov_index >= m_iov_num ||
                m_iov[m_curr_iov_index].iov_len <= m_curr_iov_offset) {
                return {nullptr, 0U};
            }
            return iovec {
                reinterpret_cast<uint8_t *>(m_iov[m_curr_iov_index].iov_base) + m_curr_iov_offset,
                m_iov[m_curr_iov_index].iov_len - m_curr_iov_offset};
        }

        pdu() = default;
        inline bool is_valid() const { return m_iov_num != 0U; }
        iovec m_iov[64U];
        /* The aux_data member contains an array of structures with message_length and mkey fields.
         * message_length indicates the start of the PDU while mkey the memory key of the
         * pre-registered memory regions. A zero mkey indicates non-registered memory.
         */
        xlio_pd_key m_aux_data[64U];
        size_t m_iov_num;
        size_t m_curr_iov_index;
        size_t m_curr_iov_offset;
        uint32_t m_seqnum;
    };

    nvmeotcp_tx(const iovec *iov, const xlio_pd_key *aux_data, size_t iov_num)
        : m_iov(iov)
        , m_aux_data(aux_data)
        , m_iov_num(iov_num)
        , m_current_pdu_iov_index(0) {};

private:
    const iovec *m_iov;
    const xlio_pd_key *m_aux_data;
    size_t m_iov_num;
    size_t m_current_pdu_iov_index;
};

class nvme_pdu_mdesc : public mem_desc {
public:
    nvme_pdu_mdesc(std::unique_ptr<nvmeotcp_tx::pdu> pdu)
        : m_pdu(std::move(pdu))
        , m_ref(1) {};

    ~nvme_pdu_mdesc() = default;

    void get(void) override { m_ref.fetch_add(1, std::memory_order_relaxed); }

    void put(void) override
    {
        int ref = m_ref.fetch_sub(1, std::memory_order_relaxed);

        if (ref == 1) {
            delete this;
        }
    }

    uint32_t get_lkey(mem_buf_desc_t *, ib_ctx_handler *, const void *addr, size_t len) override
    {
        uintptr_t addr_start = reinterpret_cast<uintptr_t>(addr);
        uintptr_t addr_end = addr_start + len;

        for (size_t i = 0; i < m_pdu->m_iov_num; i++) {
            uintptr_t range_start = reinterpret_cast<uintptr_t>(m_pdu->m_iov[i].iov_base);
            uintptr_t range_end = range_start + m_pdu->m_iov[i].iov_len;
            if (range_start <= addr_start && addr_end <= range_end) {
                return m_pdu->m_aux_data[i].mkey;
            }
        }
        return LKEY_USE_DEFAULT;
    }

    std::unique_ptr<nvmeotcp_tx::pdu> m_pdu;
    std::atomic_int m_ref;
};

#endif /* XLIO_NVME_PARSE_INPUT_ARGS_H */
