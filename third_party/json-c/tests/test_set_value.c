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

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "json.h"

int main(int argc, char **argv)
{
	json_object *tmp = doca_third_party_json_object_new_int(123);
	assert(doca_third_party_json_object_get_int(tmp) == 123);
	doca_third_party_json_object_set_int(tmp, 321);
	assert(doca_third_party_json_object_get_int(tmp) == 321);
	printf("INT PASSED\n");
	doca_third_party_json_object_set_int64(tmp, (int64_t)321321321);
	assert(doca_third_party_json_object_get_int64(tmp) == 321321321);
	doca_third_party_json_object_put(tmp);
	printf("INT64 PASSED\n");
	tmp = doca_third_party_json_object_new_uint64(123);
	assert(doca_third_party_json_object_get_boolean(tmp) == 1);
	assert(doca_third_party_json_object_get_int(tmp) == 123);
	assert(doca_third_party_json_object_get_int64(tmp) == 123);
	assert(doca_third_party_json_object_get_uint64(tmp) == 123);
	assert(doca_third_party_json_object_get_double(tmp) == 123.000000);
	doca_third_party_json_object_set_uint64(tmp, (uint64_t)321321321);
	assert(doca_third_party_json_object_get_uint64(tmp) == 321321321);
	doca_third_party_json_object_set_uint64(tmp, 9223372036854775808U);
	assert(doca_third_party_json_object_get_int(tmp) == INT32_MAX);
	assert(doca_third_party_json_object_get_uint64(tmp) == 9223372036854775808U);
	doca_third_party_json_object_put(tmp);
	printf("UINT64 PASSED\n");
	tmp = doca_third_party_json_object_new_boolean(1);
	assert(doca_third_party_json_object_get_boolean(tmp) == 1);
	doca_third_party_json_object_set_boolean(tmp, 0);
	assert(doca_third_party_json_object_get_boolean(tmp) == 0);
	doca_third_party_json_object_set_boolean(tmp, 1);
	assert(doca_third_party_json_object_get_boolean(tmp) == 1);
	doca_third_party_json_object_put(tmp);
	printf("BOOL PASSED\n");
	tmp = doca_third_party_json_object_new_double(12.34);
	assert(doca_third_party_json_object_get_double(tmp) == 12.34);
	doca_third_party_json_object_set_double(tmp, 34.56);
	assert(doca_third_party_json_object_get_double(tmp) == 34.56);
	doca_third_party_json_object_set_double(tmp, 6435.34);
	assert(doca_third_party_json_object_get_double(tmp) == 6435.34);
	doca_third_party_json_object_set_double(tmp, 2e21);
	assert(doca_third_party_json_object_get_int(tmp) == INT32_MAX);
	assert(doca_third_party_json_object_get_int64(tmp) == INT64_MAX);
	assert(doca_third_party_json_object_get_uint64(tmp) == UINT64_MAX);
	doca_third_party_json_object_set_double(tmp, -2e21);
	assert(doca_third_party_json_object_get_int(tmp) == INT32_MIN);
	assert(doca_third_party_json_object_get_int64(tmp) == INT64_MIN);
	assert(doca_third_party_json_object_get_uint64(tmp) == 0);
	doca_third_party_json_object_put(tmp);
	printf("DOUBLE PASSED\n");
#define SHORT "SHORT"
#define MID "A MID STRING"
//             12345678901234567890123456789012....
#define HUGE "A string longer than 32 chars as to check non local buf codepath"
	tmp = doca_third_party_json_object_new_string(MID);
	assert(strcmp(doca_third_party_json_object_get_string(tmp), MID) == 0);
	assert(strcmp(doca_third_party_json_object_to_json_string(tmp), "\"" MID "\"") == 0);
	doca_third_party_json_object_set_string(tmp, SHORT);
	assert(strcmp(doca_third_party_json_object_get_string(tmp), SHORT) == 0);
	assert(strcmp(doca_third_party_json_object_to_json_string(tmp), "\"" SHORT "\"") == 0);
	doca_third_party_json_object_set_string(tmp, HUGE);
	assert(strcmp(doca_third_party_json_object_get_string(tmp), HUGE) == 0);
	assert(strcmp(doca_third_party_json_object_to_json_string(tmp), "\"" HUGE "\"") == 0);
	doca_third_party_json_object_set_string(tmp, SHORT);
	assert(strcmp(doca_third_party_json_object_get_string(tmp), SHORT) == 0);
	assert(strcmp(doca_third_party_json_object_to_json_string(tmp), "\"" SHORT "\"") == 0);

	// Set an empty string a couple times to try to trigger
	// a case that used to leak memory.
	doca_third_party_json_object_set_string(tmp, "");
	doca_third_party_json_object_set_string(tmp, HUGE);
	doca_third_party_json_object_set_string(tmp, "");
	doca_third_party_json_object_set_string(tmp, HUGE);

	doca_third_party_json_object_put(tmp);
	printf("STRING PASSED\n");

#define STR "STR"
#define DOUBLE "123.123"
#define DOUBLE_E "12E+3"
#define DOUBLE_STR "123.123STR"
#define DOUBLE_OVER "1.8E+308"
#define DOUBLE_OVER_NEGATIVE "-1.8E+308"
	tmp = doca_third_party_json_object_new_string(STR);
	assert(doca_third_party_json_object_get_double(tmp) == 0.0);
	doca_third_party_json_object_set_string(tmp, DOUBLE);
	assert(doca_third_party_json_object_get_double(tmp) == 123.123000);
	doca_third_party_json_object_set_string(tmp, DOUBLE_E);
	assert(doca_third_party_json_object_get_double(tmp) == 12000.000000);
	doca_third_party_json_object_set_string(tmp, DOUBLE_STR);
	assert(doca_third_party_json_object_get_double(tmp) == 0.0);
	doca_third_party_json_object_set_string(tmp, DOUBLE_OVER);
	assert(doca_third_party_json_object_get_double(tmp) == 0.0);
	doca_third_party_json_object_set_string(tmp, DOUBLE_OVER_NEGATIVE);
	assert(doca_third_party_json_object_get_double(tmp) == 0.0);
	doca_third_party_json_object_put(tmp);
	printf("STRINGTODOUBLE PASSED\n");

	tmp = doca_third_party_json_tokener_parse("1.234");
	doca_third_party_json_object_set_double(tmp, 12.3);
	const char *serialized = doca_third_party_json_object_to_json_string(tmp);
	fprintf(stderr, "%s\n", serialized);
	assert(strncmp(serialized, "12.3", 4) == 0);
	doca_third_party_json_object_put(tmp);
	printf("PARSE AND SET PASSED\n");

	printf("PASSED\n");
	return 0;
}
