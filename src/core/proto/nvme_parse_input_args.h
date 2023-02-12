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
            if (iov != nullptr && aux_data != nullptr && m_iov_num <= 64U) {
                memcpy(&m_iov[0U], iov, m_iov_num * sizeof(*iov));
                memcpy(&m_aux_data[0U], aux_data, m_iov_num * sizeof(*aux_data));
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
            if (num_bytes == 0U || iov == nullptr || iov_num == 0U ||
                m_curr_iov_index >= m_iov_num) {
                return {0U, 0U};
            }

            size_t out_iov_idx = 0U;
            size_t remaining_num_bytes = num_bytes;
            size_t curr_iov_index = m_curr_iov_index;
            size_t curr_iov_offset = m_curr_iov_offset;
            while (remaining_num_bytes != 0U && curr_iov_index < m_iov_num &&
                   out_iov_idx < iov_num) {
                if (m_iov[curr_iov_index].iov_len == 0U ||
                    m_iov[curr_iov_index].iov_base == nullptr) {
                    curr_iov_index++;
                    continue;
                }
                iov[out_iov_idx].iov_base =
                    reinterpret_cast<uint8_t *>(m_iov[curr_iov_index].iov_base) + curr_iov_offset;
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

        /* Call this method after testing that the PDU is valid */
        inline iovec current_iov()
        {
            if (m_curr_iov_index >= m_iov_num ||
                m_iov[m_curr_iov_index].iov_len <= m_curr_iov_offset) {
                return {nullptr, 0U};
            }
            assert(m_iov[m_curr_iov_index].iov_base != nullptr);
            assert(m_iov[m_curr_iov_index].iov_len != 0);
            return iovec {
                reinterpret_cast<uint8_t *>(m_iov[m_curr_iov_index].iov_base) + m_curr_iov_offset,
                m_iov[m_curr_iov_index].iov_len - m_curr_iov_offset};
        }

        /* Call when the PDU state is known */
        inline uint32_t current_mkey() { return m_aux_data[m_curr_iov_index].mkey; }

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
    nvme_pdu_mdesc(size_t num_segments, iovec *iov, xlio_pd_key *aux_data, uint32_t seqno,
                   size_t length, std::unique_ptr<uint8_t[]> &&container)
        : m_num_segments(num_segments)
        , m_iov(iov)
        , m_aux_data(aux_data)
        , m_seqno(seqno)
        , m_length(length)
        , m_view({num_segments, 0U})
        , m_container(std::move(container))
        , m_ref(1) {};

    ~nvme_pdu_mdesc() override
    {
        m_iov = nullptr;
        m_aux_data = nullptr;
        m_container.reset();
    }

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

    uint32_t get_lkey(mem_buf_desc_t *, ib_ctx_handler *, const void *addr, size_t len) override
    {
        uintptr_t addr_start = reinterpret_cast<uintptr_t>(addr);
        uintptr_t addr_end = addr_start + len;

        auto itr = std::find_if(&m_iov[0U], &m_iov[m_num_segments], [&](const iovec &iov) {
            uintptr_t range_start = reinterpret_cast<uintptr_t>(iov.iov_base);
            uintptr_t range_end = range_start + iov.iov_len;
            return (range_start <= addr_start && addr_end <= range_end);
        });

        if (itr == &m_iov[m_num_segments]) {
            return LKEY_USE_DEFAULT;
        }
        return m_aux_data[std::distance(&m_iov[0U], itr)].mkey;
    }

    struct chunk {
        iovec iov;
        uint32_t mkey;
        chunk(void *base, size_t len, uint32_t key)
            : iov({base, len})
            , mkey(key) {};
        chunk()
            : chunk(nullptr, 0U, LKEY_USE_DEFAULT) {};
        inline bool is_valid()
        {
            return iov.iov_base != nullptr && iov.iov_len != 0U && mkey != LKEY_USE_DEFAULT;
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
    struct view {
        size_t index;
        size_t offset;
    };
    view m_view;
    std::unique_ptr<uint8_t[]> m_container;
    std::atomic_int m_ref;
};

#endif /* XLIO_NVME_PARSE_INPUT_ARGS_H */
