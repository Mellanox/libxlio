/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include "core/config/descriptors/config_descriptor.h"

/**
 * @brief Interface for providing parameter descriptors
 *
 * Abstract base class for providers that load parameter descriptors
 * from various sources (e.g., JSON schema).
 */
class descriptor_provider {
public:
    /**
     * @brief Virtual destructor
     */
    virtual ~descriptor_provider() = default;

    /**
     * @brief Loads parameter descriptors from a source
     * @return Configuration descriptor containing all parameter descriptors
     */
    virtual config_descriptor load_descriptors() = 0;
};