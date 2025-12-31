#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#

# json.m4 - Detect json-c package
#

##########################
# Checking json-c library
#
AC_DEFUN([CHECK_JSON_LIB],
[
# Use the internal json-c library built from third_party directory
AC_SUBST([LIBJSON_LIBS], "\$(top_builddir)/third_party/json-c/libjson-c.la")
AC_SUBST([LIBJSON_CFLAGS], "-I\$(top_builddir)/third_party/json-c -I\$(top_srcdir)/third_party/json-c -I\$(top_srcdir)/third_party/")
])
