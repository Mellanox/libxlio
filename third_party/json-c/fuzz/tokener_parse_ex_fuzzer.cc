/*
 * Original work:
 *
 * json-c (copyright was originally missing from this file)
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

#include <stdint.h>

#include <json.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *data1 = reinterpret_cast<const char *>(data);
	json_tokener *tok = doca_third_party_json_tokener_new();
	json_object *obj = doca_third_party_json_tokener_parse_ex(tok, data1, size);

	doca_third_party_json_object_object_foreach(jobj, key, val) {
		(void)doca_third_party_json_object_get_type(val);
		(void)doca_third_party_json_object_get_string(val);
	}
	(void)doca_third_party_json_object_to_json_string(obj, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);

	doca_third_party_json_object_put(obj);
	doca_third_party_json_tokener_free(tok);
	return 0;
}
