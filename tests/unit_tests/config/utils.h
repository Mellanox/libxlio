/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once
#include <fstream>
#include <cstdio>

class conf_file_writer {
public:
    conf_file_writer(const char *cfg_str)
    {
        std::ofstream ofs("/tmp/xlio_config.json");
        ofs << cfg_str;
    }

    const char *get() { return "/tmp/xlio_config.json"; }

    ~conf_file_writer() { std::remove("/tmp/xlio_config.json"); }
};

class env_setter {
public:
    env_setter(const char *key, const char *inline_config)
        : m_key(key)
    {
        setenv(m_key, inline_config, 1);
    }

    ~env_setter() { unsetenv(m_key); }

private:
    const char *m_key;
};
