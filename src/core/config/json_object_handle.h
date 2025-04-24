/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include <json-c/json.h>

/**
 * @brief RAII wrapper for json-c objects
 *
 * Automatically manages the lifecycle of json_object pointers,
 * ensuring proper cleanup with json_object_put().
 */
class json_object_handle {
public:
    /**
     * @brief Constructs a handle for a json object
     * @param obj Pointer to json_object to manage
     */
    explicit json_object_handle(json_object *obj);

    /**
     * @brief Destructor that releases the json object
     */
    ~json_object_handle();

    /**
     * @brief Copy constructor (deleted)
     */
    json_object_handle(const json_object_handle &) = delete;

    /**
     * @brief Assignment operator (deleted)
     */
    json_object_handle &operator=(const json_object_handle &) = delete;

    /**
     * @brief Gets the underlying json object pointer
     * @return Raw pointer to the json_object
     */
    json_object *get() const;

    /**
     * @brief Boolean conversion operator
     * @return True if the handle contains a valid object, false otherwise
     */
    operator bool() const;

private:
    json_object *m_obj; /**< Managed json object pointer */
};