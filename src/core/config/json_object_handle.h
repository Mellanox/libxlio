/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include <json-c/json.h>

class json_object_handle {
public:
    explicit json_object_handle(json_object *obj);
    ~json_object_handle();

    json_object_handle(const json_object_handle &) = delete;
    json_object_handle &operator=(const json_object_handle &) = delete;

    json_object *get() const;

    operator bool() const;

private:
    json_object *m_obj;
};