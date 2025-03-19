/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef XLIO_TI_H
#define XLIO_TI_H

#include <cstdint>
#include <memory>
#include <assert.h>
#include <mellanox/dpcp.h>

/* Work request completion callback */
/* TODO Add argument for completion status to handle errors. */
typedef void (*xlio_comp_cb_t)(void *);

class xlio_ti;

class xlio_ti_owner {
public:
    virtual void ti_released(xlio_ti *ti) = 0;
};

class xlio_ti {
public:
    enum ti_type : uint8_t { UNKNOWN, TLS_TIS, TLS_TIR, NVME_TIS, NVME_TIR };

    xlio_ti(xlio_ti_owner *ti_owner, ti_type type = UNKNOWN)
        : m_ti_owner(ti_owner)
        , m_type(type)
        , m_released(false)
        , m_ref(0)
        , m_callback(nullptr)
        , m_callback_arg(nullptr)
    {
    }

    virtual ~xlio_ti() {};

    void assign_callback(xlio_comp_cb_t callback, void *callback_arg)
    {
        m_callback = callback;
        m_callback_arg = callback_arg;
    }

    /*
     * Reference counting. m_ref must be protected by ring tx lock. Device
     * layer (QP, CQ) is responsible for the reference counting.
     */

    void get()
    {
        ++m_ref;
        assert(m_ref > 0);
    }

    uint32_t put()
    {
        assert(m_ref > 0);
        return --m_ref;
    }

    void ti_released() { m_ti_owner->ti_released(this); }

    xlio_ti_owner *const m_ti_owner;
    ti_type m_type;
    bool m_released;
    uint32_t m_ref;

    xlio_comp_cb_t m_callback;
    void *m_callback_arg;
};

class xlio_tis : public xlio_ti {
public:
    xlio_tis(xlio_ti_owner *ti_owner, std::unique_ptr<dpcp::tis> _tis, xlio_ti::ti_type type)
        : xlio_ti(ti_owner, type)
        , m_dek()
        , m_p_tis(std::move(_tis))
        , m_tisn(0U)
        , m_dek_id(0U)
    {
        dpcp::status ret = m_p_tis->get_tisn(m_tisn);
        assert(ret == dpcp::DPCP_OK);
        (void)ret;
    }

    ~xlio_tis() = default;

    std::unique_ptr<dpcp::dek> release_dek()
    {
        assert(m_ref == 0);
        m_released = false;
        return std::move(m_dek);
    }

    uint32_t get_tisn() noexcept { return m_tisn; }

    void assign_dek(std::unique_ptr<dpcp::dek> &&dek_ptr)
    {
        m_dek = std::move(dek_ptr);
        m_dek_id = m_dek->get_key_id();
    }

    uint32_t get_dek_id() noexcept { return m_dek_id; }

private:
    std::unique_ptr<dpcp::dek> m_dek;
    std::unique_ptr<dpcp::tis> m_p_tis;
    uint32_t m_tisn;
    uint32_t m_dek_id;
};

class xlio_tir : public xlio_ti {
public:
    xlio_tir(xlio_ti_owner *ti_owner, dpcp::tir *dpcp_tir, xlio_ti::ti_type type)
        : xlio_ti(ti_owner, type)
    {
        m_p_tir.reset(dpcp_tir);
        m_dek = NULL;
        m_tirn = 0;
        m_dek_id = 0;

        /* Cache the tir number. Mustn't fail for a valid TIR object. */
        m_tirn = m_p_tir->get_tirn();
        assert(m_tirn != 0);
    }

    ~xlio_tir() = default;

    std::unique_ptr<dpcp::dek> release_dek()
    {
        assert(m_ref == 0);
        m_released = false;
        return std::move(m_dek);
    }

    uint32_t get_tirn() { return m_tirn; }

    void assign_dek(void *dek_ptr)
    {
        m_dek.reset(reinterpret_cast<dpcp::dek *>(dek_ptr));
        m_dek_id = m_dek->get_key_id();
    }

    uint32_t get_dek_id() { return m_dek_id; }

    std::unique_ptr<dpcp::tir> m_p_tir;

private:
    std::unique_ptr<dpcp::dek> m_dek;
    uint32_t m_tirn;
    uint32_t m_dek_id;
};

#endif // XLIO_TI_H
