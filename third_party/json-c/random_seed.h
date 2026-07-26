/*
 * Original work:
 *
 * random_seed.h
 *
 * Copyright (c) 2013 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 * Modified Work:
 *
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

/**
 * @file
 * @brief Do not use, json-c internal, may be changed or removed at any time.
 */
#ifndef seed_h
#define seed_h

#ifdef __cplusplus
extern "C" {
#endif

extern int doca_third_party_json_c_get_random_seed(void);

#ifdef __cplusplus
}
#endif

#endif
