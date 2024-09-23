#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# nl.m4 - Detect nl package
#

##########################
# Checking nl library
#
AC_DEFUN([CHECK_NL_LIB],
[
# checking for libnl1 or libnl3 in libibverbs
if test -f "$ac_cv_ofed_path/lib64/libibverbs.so" ; then
	libibverbs_file="$ac_cv_ofed_path/lib64/libibverbs.so"
elif test -f "$(ls -d $ac_cv_ofed_path/lib/$(uname -m)-linux-*)/libibverbs.so" ; then
	libibverbs_file="$(ls -d $ac_cv_ofed_path/lib/$(uname -m)-linux-*)/libibverbs.so"
else
	libibverbs_file="$ac_cv_ofed_path/lib/libibverbs.so"
fi

PKG_CHECK_MODULES([LIBNL3],[libnl-route-3.0])

AC_SUBST([LIBNL_LIBS], "$LIBNL3_LIBS")
AC_SUBST([LIBNL_CFLAGS], "$LIBNL3_CFLAGS")

ldd $libibverbs_file | grep libnl >/dev/null 2>&1
if test $? -eq 0 ; then
	# When linking with libibverbs library, we must ensure that we pick the same version
	# of libnl that libibverbs picked. libxlio requires libnl-3, so libnl-1 is not supported
	ldd $libibverbs_file | grep -e 'libnl3' -e 'libnl-3' >/dev/null 2>&1
	if test $? -ne 0 ; then
		# libnl1 case
		AC_MSG_ERROR([libibverbs is linked with unsupported libnl version (libnl3 is required)])
	fi
fi

])
