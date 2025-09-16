/*
 * Original work:
 *
 * Copyright (C) 2016 by Rainer Gerhards
 * Released under ASL 2.0 *
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
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "config.h"
#include "json_object.h"
#include "json_tokener.h"
#include <stdio.h>
int main(void)
{
	json_object *json;

	json = doca_third_party_json_object_new_double(1.0);
	printf("json = %s\n", doca_third_party_json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY));
	doca_third_party_json_object_put(json);

	json = doca_third_party_json_object_new_double(-1.0);
	printf("json = %s\n", doca_third_party_json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY));
	doca_third_party_json_object_put(json);
	json = doca_third_party_json_object_new_double(1.23);
	printf("json = %s\n", doca_third_party_json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY));
	doca_third_party_json_object_put(json);
	json = doca_third_party_json_object_new_double(123456789.0);
	printf("json = %s\n", doca_third_party_json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY));
	doca_third_party_json_object_put(json);
	json = doca_third_party_json_object_new_double(123456789.123);
	printf("json = %s\n", doca_third_party_json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY));
	doca_third_party_json_object_put(json);
	return 0;
}
