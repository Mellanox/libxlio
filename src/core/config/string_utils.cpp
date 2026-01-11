/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "string_utils.h"
#include <algorithm>
#include <sstream>
#include <vector>

namespace string_utils {

std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream stream(s);

    while (std::getline(stream, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }

    return tokens;
}

size_t levenshtein_distance(const std::string &s1, const std::string &s2)
{
    const size_t len1 = s1.size();
    const size_t len2 = s2.size();

    // Create a distance matrix
    std::vector<size_t> col(len2 + 1);
    std::vector<size_t> prev_col(len2 + 1);

    // Initialize the first column
    for (size_t i = 0; i < prev_col.size(); i++) {
        prev_col[i] = i;
    }

    // Calculate distances
    for (size_t i = 0; i < len1; i++) {
        col[0] = i + 1;
        for (size_t j = 0; j < len2; j++) {
            col[j + 1] =
                std::min({prev_col[j + 1] + 1, col[j] + 1, prev_col[j] + (s1[i] == s2[j] ? 0 : 1)});
        }
        col.swap(prev_col);
    }

    return prev_col[len2];
}

} // namespace string_utils
