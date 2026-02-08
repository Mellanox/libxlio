/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <map>
#include <string>

#include "change_reason.h"
#include "config_registry.h"
#include "config_var_info.h"
#include "core/util/xlio_exception.h"

/**
 * @brief Runtime registry holding a reference to config_registry and, for every key,
 * a pointer to a place holding it's actual value at run-time.
 */
class runtime_registry {
public:
    // Type of a translator from config registry type to runtime type
    template <typename REGISTRY_T, typename RUNTIME_T = REGISTRY_T>
    using translator_c2r_t = std::function<RUNTIME_T(REGISTRY_T, const std::string &key)>;
    // Type of a translator from runtime type to config registry type
    template <typename RUNTIME_T, typename REGISTRY_T = RUNTIME_T>
    using translator_r2c_t = std::function<REGISTRY_T(RUNTIME_T)>;
    // Type of a char array: pointer to the array and its size
    typedef std::pair<void *, size_t> char_array_t;

    explicit runtime_registry();

    config_registry &get_config_registry() { return m_config_registry; }
    const config_registry &get_config_registry() const { return m_config_registry; }

    /**
     * @brief Registers a pointer for the given key and initializes the pointed-to variable
     *        with the default value from config_registry.
     * @tparam RUNTIME_T Type of the variable
     * @tparam REGISTRY_TYPE_T Type of the variable in config registry.
     *         Must be one of: int64_t, bool, std::string
     * @param ptr Pointer to the variable to register and initialize
     * @param key Configuration key
     * @param translator_config_registry_to_runtime Optional translator from config registry type to
     *         runtime type. If not given, No translator is used.
     * @param translator_runtime_to_config_registry Optional translator from runtime type to config
     * registry type. If not given, No translator is used.
     * @throws xlio_exception if the key already exists in the map
     */
    template <typename RUNTIME_T, typename REGISTRY_T = RUNTIME_T>
    void register_and_set_default_value(
        RUNTIME_T *runtime_pointer, const config_var_info_t<RUNTIME_T, REGISTRY_T> &key,
        translator_c2r_t<REGISTRY_T, RUNTIME_T> translator_config_registry_to_runtime = nullptr,
        translator_r2c_t<RUNTIME_T, REGISTRY_T> translator_runtime_to_config_registry = nullptr)
    {
        static_assert(std::is_same<REGISTRY_T, int64_t>::value ||
                          std::is_same<REGISTRY_T, bool>::value ||
                          std::is_same<REGISTRY_T, std::string>::value,
                      "REGISTRY_T must be int64_t, bool, or std::string");

        register_pointer_and_check_duplicates(key.name, runtime_pointer);
        m_runtime_values[key.name] =
            runtime_entry_t {std::make_unique<runtime_integer_t<RUNTIME_T, REGISTRY_T>>(
                                 runtime_pointer, std::move(translator_config_registry_to_runtime),
                                 std::move(translator_runtime_to_config_registry)),
                             change_reason::NotChanged};
        m_runtime_values[key.name].value_adapter->set_default_value_from_config_registry(
            m_config_registry, key.name);
    }

    /**
     * @brief Registers a pointer for the given key and initializes the pointed-to char array
     *        with the default value from config_registry.
     * @param char_array Pointer to the char array to register and initialize
     * @param size Size of the char array
     * @param key Configuration key
     * @throws xlio_exception if the key already exists in the map
     */
    void register_char_array_and_set_default_value(char *char_array, size_t size,
                                                   const config_var_info_t<std::string> &key);

    /**
     * @brief Registers a pointer for the given key and initializes the pointed-to char array
     *        to a specific value.
     *        This also marks the key as "explicitly set", so it will not be overridden by the
     *        default or user-set values from config_registry.
     * @param char_array Pointer to the char array to register and initialize
     * @param size Size of the char array
     * @param key Configuration key
     * @param value value to set the char array to
     * @throws xlio_exception if the key already exists in the map
     */
    void register_char_array_and_set_explicit_value(char *char_array, size_t size,
                                                    const config_var_info_t<std::string> &key,
                                                    const std::string &value);

    /**
     * @brief Sets the value for the given key if it exists in the config registry.
     * @param key Configuration key name
     * @throws xlio_exception if the key is not registered into the runtime registry
     */
    void set_value_if_exists(const std::string &key);

    /**
     * @brief Iterates over all registered keys, and sets the value for each key if it exists in the
     * config registry.
     */
    void set_all_configured_values();

    /**
     * @brief Gets the value of the runtime value as std::experimental::any
     * @param key Configuration key name
     * @return Value of the runtime value as std::experimental::any
     * @throws xlio_exception if the key is not registered into the runtime registry
     */
    std::experimental::any get_value_as_any(const std::string &key) const;

    /**
     * @brief Sets the value for the given key (key-based API with reason and description).
     * @param key Configuration key name
     * @param value Value (Must be one of: int64_t, bool, std::string)
     * @param reason Reason for the change (ConfigurationFile, Profile, AutoCorrected)
     * @param description Human-readable description (e.g. "From config file")
     * @throws xlio_exception if the key is not registered into the runtime registry
     */
    template <typename RUNTIME_T, typename REGISTRY_T = RUNTIME_T>
    void set_value(const config_var_info_t<RUNTIME_T, REGISTRY_T> &key, REGISTRY_T value,
                   change_reason::change_reason_t reason, const std::string &description)
    {
        static_assert(std::is_same<REGISTRY_T, int64_t>::value ||
                          std::is_same<REGISTRY_T, bool>::value ||
                          std::is_same<REGISTRY_T, std::string>::value,
                      "REGISTRY_T must be int64_t, bool, or std::string");
        set_value_from_any(key.name, std::experimental::any(value), reason, description);
    }

    /**
     * @brief Returns the last change reason for the given key.
     * @param key Configuration key name
     * @return change_reason::change_reason_t (NotChanged until a change is recorded)
     * @throws xlio_exception if the key is not registered into the runtime registry
     */
    change_reason::change_reason_t get_last_change_reason(const std::string &key) const;

    /**
     * @brief Checks if the given key is registered in the runtime registry.
     * @param key Configuration key name
     * @return true if it is registered, false otherwise
     */
    bool is_registered(const std::string &key) const;

private:
    /**
     * @brief Sets the value for the given key from an any (type must match registry type: int64_t,
     * bool, std::string)
     * @param key Configuration key name
     * @param value Value as std::experimental::any (must match registry type: int64_t, bool,
     * std::string)
     * @param reason Reason for the change (ConfigurationFile, Profile, AutoCorrected)
     * @param description Human-readable description (e.g. "From config file")
     * @throws xlio_exception if the key is not registered into the runtime registry
     */
    void set_value_from_any(const std::string &key, const std::experimental::any &value,
                            change_reason::change_reason_t reason, const std::string &description);

    /**
     * @brief Registers the runtime pointer in a map used for duplication detection.
     * Checks if any of the parameters already exists in the runtime registry
     * @param key Configuration key name
     * @param runtime_pointer Pointer to the runtime value
     * @throws xlio_exception if the key already exists in the map, or if the runtime pointer is
     * already registered
     */
    void register_pointer_and_check_duplicates(const std::string &key, void *runtime_pointer);

    class runtime_base_t;

    struct runtime_entry_t {
        std::unique_ptr<runtime_base_t> value_adapter;
        change_reason::change_reason_t last_change_reason {change_reason::NotChanged};
    };

    /* @brief Base class for all runtime values.
     * For a given key, holds a pointer to the runtime value, and optional translator from the
     * config registry type. It knows how to move a value from the config registry to the runtime
     * value.
     */
    class runtime_base_t {
    public:
        virtual ~runtime_base_t() = default;

        // Sets default value from config registry to the runtime value
        virtual void set_default_value_from_config_registry(config_registry &config_registry,
                                                            const std::string &key) = 0;
        // Sets value from config registry, if such a value is set, to the runtime value.
        // @return true if the value was set, false otherwise
        virtual bool set_value_from_config_registry_if_exists(config_registry &config_registry,
                                                              const std::string &key) = 0;
        // Sets the runtime value from an any (type must match registry type: int64_t, bool,
        // std::string)
        virtual void set_value_from_any(const std::experimental::any &value) = 0;
        // Returns the runtime value as std::experimental::any
        // Encapsulated type is the config registry type: can be a bool, int64_t, or std::string
        virtual std::experimental::any get_value_as_any() const = 0;
        // Returns the runtime value as std::string
        virtual std::string get_value_as_string() const = 0;
    };

    // Implementation of runtime_base_t for a basic integer type
    // RUNTIME_T is a basic integer type, or bool
    template <typename RUNTIME_T, typename REGISTRY_T = RUNTIME_T>
    class runtime_integer_t : public runtime_base_t {
    public:
        runtime_integer_t(RUNTIME_T *ptr, translator_c2r_t<REGISTRY_T, RUNTIME_T> translator_c2r,
                          translator_r2c_t<RUNTIME_T, REGISTRY_T> translator_r2c)
            : m_ptr(ptr)
            , m_translator_config_registry_to_runtime(std::move(translator_c2r))
            , m_translator_runtime_to_config_registry(std::move(translator_r2c))
        {
        }

        void set_default_value_from_config_registry(config_registry &config_registry,
                                                    const std::string &key) override
        {
            REGISTRY_T default_value = config_registry.get_default_value<REGISTRY_T>(key);
            set_value(default_value, key);
        }

        bool set_value_from_config_registry_if_exists(config_registry &config_registry,
                                                      const std::string &key) override
        {
            if (config_registry.value_exists(key)) {
                REGISTRY_T value = config_registry.get_value<REGISTRY_T>(key);
                set_value(value, key);
                return true;
            }
            return false;
        }

        void set_value_from_any(const std::experimental::any &value) override
        {
            set_value(std::experimental::any_cast<REGISTRY_T>(value), "");
        }

        std::experimental::any get_value_as_any() const override
        {
            REGISTRY_T config_value;
            if (m_translator_runtime_to_config_registry) {
                config_value = m_translator_runtime_to_config_registry(*m_ptr);
            } else {
                config_value = static_cast<REGISTRY_T>(*m_ptr);
            }
            return std::experimental::any(config_value);
        }

        std::string get_value_as_string() const override { return std::to_string(*m_ptr); }

    private:
        // Holds the pointer to the runtime value
        RUNTIME_T *m_ptr;
        // Optional translators from config registry type to runtime type, and back
        translator_c2r_t<REGISTRY_T, RUNTIME_T> m_translator_config_registry_to_runtime;
        translator_r2c_t<RUNTIME_T, REGISTRY_T> m_translator_runtime_to_config_registry;

        void set_value(REGISTRY_T value, const std::string &key)
        {
            RUNTIME_T runtime_value;
            if (m_translator_config_registry_to_runtime) {
                runtime_value = m_translator_config_registry_to_runtime(value, key);
            } else {
                runtime_value = static_cast<RUNTIME_T>(value);
            }
            *m_ptr = runtime_value;
        }
    };

    // Implementation of runtime_base_t for a char array
    class runtime_char_array_t : public runtime_base_t {
    public:
        runtime_char_array_t(char *ptr, size_t size, bool explicitly_set)
            : m_ptr(ptr)
            , m_size(size)
            , m_explicitly_set(explicitly_set)
        {
        }

        void set_default_value_from_config_registry(config_registry &config_registry,
                                                    const std::string &key) override;

        bool set_value_from_config_registry_if_exists(config_registry &config_registry,
                                                      const std::string &key) override;

        void set_value_from_any(const std::experimental::any &value) override;

        std::experimental::any get_value_as_any() const override;

        std::string get_value_as_string() const override;

    private:
        // Holds the pointer to the runtime value
        char *m_ptr {nullptr};
        size_t m_size {0};
        bool m_explicitly_set {false};

        void set_value(const std::string &value);
    };

    config_registry m_config_registry;

    // Map of runtime values
    // Key is name of config parameter
    // Value is runtime_entry_t (value_adapter + last_change_reason)
    std::map<std::string, runtime_entry_t> m_runtime_values;

    // Map of all pointers, used to detect duplications
    // Key is pointer to the runtime value
    // Value is name of config parameter
    std::map<void *, std::string> m_all_pointers;
};
