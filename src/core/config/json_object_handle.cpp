/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "json_object_handle.h"

json_object_handle::json_object_handle(json_object *obj)
    : m_obj(obj)
{
}

json_object_handle::~json_object_handle()
{
    if (m_obj) {
        json_object_put(m_obj);
    }
}

json_object *json_object_handle::get() const
{
    return m_obj;
}

json_object_handle::operator bool() const
{
    return m_obj != nullptr;
}
