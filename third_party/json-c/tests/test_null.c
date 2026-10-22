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

/*
 * Tests if binary strings are supported.
 */

#ifdef NDEBUG
#undef NDEBUG
#endif
#include "config.h"
#include <stdio.h>
#include <string.h>

#include "json_inttypes.h"
#include "json_object.h"
#include "json_tokener.h"

int main(void)
{
	/* this test has a space after the null character. check that it's still included */
	const char *input = " \0 ";
	const char *expected = "\" \\u0000 \"";
	struct json_object *string = doca_third_party_json_object_new_string_len(input, 3);
	const char *json = doca_third_party_json_object_to_json_string(string);

	int strings_match = !strcmp(expected, json);
	int retval = 0;
	if (strings_match)
	{
		printf("JSON write result is correct: %s\n", json);
		puts("PASS");
	}
	else
	{
		puts("JSON write result doesn't match expected string");
		printf("expected string: ");
		puts(expected);
		printf("parsed string:   ");
		puts(json);
		puts("FAIL");
		retval = 1;
	}
	doca_third_party_json_object_put(string);

	struct json_object *parsed_str = doca_third_party_json_tokener_parse(expected);
	if (parsed_str)
	{
		int parsed_len = doca_third_party_json_object_get_string_len(parsed_str);
		const char *parsed_cstr = doca_third_party_json_object_get_string(parsed_str);
		int ii;
		printf("Re-parsed object string len=%d, chars=[", parsed_len);
		for (ii = 0; ii < parsed_len; ii++)
		{
			printf("%s%d", (ii ? ", " : ""), (int)parsed_cstr[ii]);
		}
		puts("]");
		doca_third_party_json_object_put(parsed_str);
	}
	else
	{
		puts("ERROR: failed to parse");
	}
	return retval;
}
