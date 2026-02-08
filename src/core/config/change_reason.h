/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

/**
 * @brief Reason for a configuration value change (used by runtime_registry and config_printer).
 */
struct change_reason {
    enum change_reason_t { NotChanged, ConfigurationFile, Profile, AutoCorrected };

    /**
     * @brief Returns a human-readable string for the given change reason.
     */
    static const char *to_string(change_reason_t reason)
    {
        switch (reason) {
        case NotChanged:
            return "Not-changed";
        case ConfigurationFile:
            return "Configuration-file";
        case Profile:
            return "Profile";
        case AutoCorrected:
            return "Auto-Corrected";
        }
        return "Unknown";
    }
};
