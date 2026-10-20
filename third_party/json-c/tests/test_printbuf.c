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
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "printbuf.h"

static void test_basic_printbuf_memset(void);
static void test_printbuf_memset_length(void);

#ifndef __func__
/* VC++ compat */
#define __func__ __FUNCTION__
#endif

static void test_basic_printbuf_memset(void)
{
	struct printbuf *pb;

	printf("%s: starting test\n", __func__);
	pb = doca_third_party_printbuf_new();
	doca_third_party_sprintbuf(pb, "blue:%d", 1);
	doca_third_party_printbuf_memset(pb, -1, 'x', 52);
	printf("Buffer contents:%.*s\n", printbuf_length(pb), pb->buf);
	doca_third_party_printbuf_free(pb);
	printf("%s: end test\n", __func__);
}

static void test_printbuf_memset_length(void)
{
	struct printbuf *pb;

	printf("%s: starting test\n", __func__);
	pb = doca_third_party_printbuf_new();
	doca_third_party_printbuf_memset(pb, -1, ' ', 0);
	doca_third_party_printbuf_memset(pb, -1, ' ', 0);
	doca_third_party_printbuf_memset(pb, -1, ' ', 0);
	doca_third_party_printbuf_memset(pb, -1, ' ', 0);
	doca_third_party_printbuf_memset(pb, -1, ' ', 0);
	printf("Buffer length: %d\n", printbuf_length(pb));
	doca_third_party_printbuf_memset(pb, -1, ' ', 2);
	doca_third_party_printbuf_memset(pb, -1, ' ', 4);
	doca_third_party_printbuf_memset(pb, -1, ' ', 6);
	printf("Buffer length: %d\n", printbuf_length(pb));
	doca_third_party_printbuf_memset(pb, -1, ' ', 6);
	printf("Buffer length: %d\n", printbuf_length(pb));
	doca_third_party_printbuf_memset(pb, -1, ' ', 8);
	doca_third_party_printbuf_memset(pb, -1, ' ', 10);
	doca_third_party_printbuf_memset(pb, -1, ' ', 10);
	doca_third_party_printbuf_memset(pb, -1, ' ', 10);
	doca_third_party_printbuf_memset(pb, -1, ' ', 20);
	printf("Buffer length: %d\n", printbuf_length(pb));

	// No length change should occur
	doca_third_party_printbuf_memset(pb, 0, 'x', 30);
	printf("Buffer length: %d\n", printbuf_length(pb));

	// This should extend it by one.
	doca_third_party_printbuf_memset(pb, 0, 'x', printbuf_length(pb) + 1);
	printf("Buffer length: %d\n", printbuf_length(pb));

	doca_third_party_printbuf_free(pb);
	printf("%s: end test\n", __func__);
}

static void test_printbuf_memappend(int *before_resize);
static void test_printbuf_memappend(int *before_resize)
{
	struct printbuf *pb;
	int initial_size;

	printf("%s: starting test\n", __func__);
	pb = doca_third_party_printbuf_new();
	printf("Buffer length: %d\n", printbuf_length(pb));

	initial_size = pb->size;

	while (pb->size == initial_size)
	{
		printbuf_memappend_fast(pb, "x", 1);
	}
	*before_resize = printbuf_length(pb) - 1;
	printf("Appended %d bytes for resize: [%s]\n", *before_resize + 1, pb->buf);

	doca_third_party_printbuf_reset(pb);
	printbuf_memappend_fast(pb, "bluexyz123", 3);
	printf("Partial append: %d, [%s]\n", printbuf_length(pb), pb->buf);

	char with_nulls[] = {'a', 'b', '\0', 'c'};
	doca_third_party_printbuf_reset(pb);
	printbuf_memappend_fast(pb, with_nulls, (int)sizeof(with_nulls));
	printf("With embedded \\0 character: %d, [%s]\n", printbuf_length(pb), pb->buf);

	doca_third_party_printbuf_free(pb);
	pb = doca_third_party_printbuf_new();
	char *data = malloc(*before_resize);
	memset(data, 'X', *before_resize);
	printbuf_memappend_fast(pb, data, *before_resize);
	printf("Append to just before resize: %d, [%s]\n", printbuf_length(pb), pb->buf);

	free(data);
	doca_third_party_printbuf_free(pb);

	pb = doca_third_party_printbuf_new();
	data = malloc(*before_resize + 1);
	memset(data, 'X', *before_resize + 1);
	printbuf_memappend_fast(pb, data, *before_resize + 1);
	printf("Append to just after resize: %d, [%s]\n", printbuf_length(pb), pb->buf);

	free(data);
	doca_third_party_printbuf_free(pb);

#define SA_TEST_STR "XXXXXXXXXXXXXXXX"
	pb = doca_third_party_printbuf_new();
	printbuf_strappend(pb, SA_TEST_STR);
	printf("Buffer size after printbuf_strappend(): %d, [%s]\n", printbuf_length(pb), pb->buf);
	doca_third_party_printbuf_free(pb);
#undef SA_TEST_STR

	printf("%s: end test\n", __func__);
}

static void test_sprintbuf(int before_resize);
static void test_sprintbuf(int before_resize)
{
	struct printbuf *pb;
	const char *max_char =
	    "if string is greater than stack buffer, then use dynamic string"
	    " with vasprintf.  Note: some implementation of vsnprintf return -1 "
	    " if output is truncated whereas some return the number of bytes that "
	    " would have been written - this code handles both cases.";

	printf("%s: starting test\n", __func__);
	pb = doca_third_party_printbuf_new();
	printf("Buffer length: %d\n", printbuf_length(pb));

	char *data = malloc(before_resize + 1 + 1);
	memset(data, 'X', before_resize + 1 + 1);
	data[before_resize + 1] = '\0';
	doca_third_party_sprintbuf(pb, "%s", data);
	free(data);
	printf("sprintbuf to just after resize(%d+1): %d, [%s], strlen(buf)=%d\n", before_resize,
	       printbuf_length(pb), pb->buf, (int)strlen(pb->buf));

	doca_third_party_printbuf_reset(pb);
	doca_third_party_sprintbuf(pb, "plain");
	printf("%d, [%s]\n", printbuf_length(pb), pb->buf);

	doca_third_party_sprintbuf(pb, "%d", 1);
	printf("%d, [%s]\n", printbuf_length(pb), pb->buf);

	doca_third_party_sprintbuf(pb, "%d", INT_MAX);
	printf("%d, [%s]\n", printbuf_length(pb), pb->buf);

	doca_third_party_sprintbuf(pb, "%d", INT_MIN);
	printf("%d, [%s]\n", printbuf_length(pb), pb->buf);

	doca_third_party_sprintbuf(pb, "%s", "%s");
	printf("%d, [%s]\n", printbuf_length(pb), pb->buf);

	doca_third_party_sprintbuf(pb, max_char);
	printf("%d, [%s]\n", printbuf_length(pb), pb->buf);
	doca_third_party_printbuf_free(pb);
	printf("%s: end test\n", __func__);
}

int main(int argc, char **argv)
{
	int before_resize = 0;

	MC_SET_DEBUG(1);

	test_basic_printbuf_memset();
	printf("========================================\n");
	test_printbuf_memset_length();
	printf("========================================\n");
	test_printbuf_memappend(&before_resize);
	printf("========================================\n");
	test_sprintbuf(before_resize);
	printf("========================================\n");

	return 0;
}
