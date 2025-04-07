/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "config_provider.h"
#include "descriptor_providers/descriptor_provider.h"
#include "descriptors/config_descriptor.h"
#include "loaders/loader.h"
#include <experimental/any>
#include <map>
#include <memory>
#include <queue>

class config_registry : public config_provider {
public:
  config_registry(std::queue<std::unique_ptr<loader>> &&value_loaders,
                  std::unique_ptr<descriptor_provider> descriptor_provider);

  config_registry();
  ~config_registry() override = default;

protected:
  std::experimental::any
  get_value_as_any(const std::string &key) const override;

private:
  std::map<std::string, std::experimental::any> m_config_data;
  config_descriptor m_config_descriptor;

  void validate_config() const;
  void
  initialize_registry(std::queue<std::unique_ptr<loader>> &&value_loaders,
                      std::unique_ptr<descriptor_provider> descriptor_provider);
};
