#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

# dpcp.m4 - Library to operate with DevX
# 

##########################
# libdpcp usage support
#
AC_DEFUN([DPCP_CAPABILITY_SETUP],
[

prj_cv_dpcp=0
prj_cv_dpcp_CPPFLAGS=""
prj_cv_dpcp_LDFLAGS=""

get_version_number()
{
    dpcp_cv_token=`grep dpcp_version "${with_dpcp}/include/mellanox/dpcp.h" | sed -n 's/^.*\([[0-9]]\+\.[[0-9]]\+\.[[0-9]]\+\).*$/\1/p' `

    if egrep '^[[0-9]]+\.[[0-9]]+\.[[0-9]]+' <<<"$dpcp_cv_token" >/dev/null 2>&1 ; then
        # It has the correct syntax.
        n=${dpcp_cv_token//[[!0-9]]/ }
        v=(${n//\./ })

        echo "$((${v[[0]]} * 10000 + ${v[[1]]} * 100 + ${v[[2]]}))"
    else
        echo 0
    fi
}

get_min_supported_version()
{
    echo 10143
}

verify_dpcp_header_exists()
{
    prj_cv_dpcp_save_CPPFLAGS="$CPPFLAGS"
    prj_cv_dpcp_save_CXXFLAGS="$CXXFLAGS"
    prj_cv_dpcp_save_CFLAGS="$CFLAGS"
    prj_cv_dpcp_save_LDFLAGS="$LDFLAGS"
    prj_cv_dpcp_save_LIBS="$LIBS"

    prj_cv_dpcp_LIBS="-ldpcp -lmlx5 -libverbs -lgcov"
    if test -d "$with_dpcp/lib64"; then
        prj_cv_dpcp_LDFLAGS="-L$with_dpcp/lib64 -Wl,--rpath,$with_dpcp/lib64"
    fi

    CPPFLAGS="$prj_cv_dpcp_CPPFLAGS $CPPFLAGS"
    LDFLAGS="$prj_cv_dpcp_LDFLAGS $LDFLAGS"
    LIBS="$prj_cv_dpcp_LIBS $LIBS"

    AC_LANG_PUSH([C++])
    AC_CHECK_HEADER(
        [mellanox/dpcp.h],
        [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <mellanox/dpcp.h>]],
                [[dpcp::provider *provider;
                dpcp::provider::get_instance(provider);]])],
                [prj_cv_dpcp=1])
        ])
    AC_LANG_POP()

    CPPFLAGS="$prj_cv_dpcp_save_CPPFLAGS"
    CXXFLAGS="$prj_cv_dpcp_save_CXXFLAGS"
    CFLAGS="$prj_cv_dpcp_save_CFLAGS"
    LDFLAGS="$prj_cv_dpcp_save_LDFLAGS"
    LIBS="$prj_cv_dpcp_save_LIBS"
}

AC_ARG_WITH([dpcp],
    AS_HELP_STRING([--with-dpcp@<:@=DIR@:>@],
                   [Search for dpcp headers and libraries in DIR @<:@default: /usr@:>@]),
    [
        with_dpcp=$withval
        if test -z "$with_dpcp" || test "$with_dpcp" = "yes"; then
            with_dpcp=/usr
        fi

        FUNC_CHECK_WITHDIR([dpcp], [$with_dpcp], [include/mellanox/dpcp.h])

        prj_cv_dpcp_CPPFLAGS="-I$with_dpcp/include"
        prj_cv_dpcp_LDFLAGS="-L$with_dpcp/lib -Wl,--rpath,$with_dpcp/lib"
        verify_dpcp_header_exists
        if test "$prj_cv_dpcp" -ne 0; then
            CPPFLAGS="$CPPFLAGS $prj_cv_dpcp_CPPFLAGS"
            LDFLAGS="$prj_cv_dpcp_LDFLAGS $LDFLAGS"
            AC_SUBST([DPCP_LIBS], ["-ldpcp"])
            dpcp_version_number=($(get_version_number))
            min_supported_version=($(get_min_supported_version))

            if test "$dpcp_version_number" -ge "$min_supported_version"; then
                AC_DEFINE_UNQUOTED([DEFINED_DPCP_MIN], [$min_supported_version], [Define to DPCP version number (major * 10000 + minor * 100 + patch)])
                AC_ARG_ENABLE([dpcp-rx], AS_HELP_STRING([--enable-dpcp-rx], [Enable DPCP RX when using with-dpcp (default=yes)]), [], [enable_dpcp_rx=yes])
                AC_ARG_ENABLE([dpcp-tx], AS_HELP_STRING([--enable-dpcp-tx], [Enable DPCP TX when using with-dpcp (default=yes)]), [], [enable_dpcp_tx=yes])

                if test "x$enable_dpcp_rx" = xyes; then
                    AC_DEFINE_UNQUOTED([DEFINED_DPCP_PATH_RX], [1], [Enable DPCP RX data path])
                fi

                if test "x$enable_dpcp_tx" = xyes; then
                    AC_DEFINE_UNQUOTED([DEFINED_DPCP_PATH_TX], [1], [Enable DPCP TX data path])
                fi
            else
                AC_MSG_ERROR([found incompatible dpcp version $dpcp_version_number (min supported version $min_supported_version) ])
            fi
        else
            AC_MSG_ERROR([dpcp support requested but not present])
        fi
    ],
    []
)

AM_CONDITIONAL([DEFINED_DPCP_PATH_RX], [test "x$enable_dpcp_rx" = xyes])
AM_CONDITIONAL([DEFINED_DPCP_PATH_TX], [test "x$enable_dpcp_tx" = xyes])
# DPCP TX or RX or both
AM_CONDITIONAL([DEFINED_DPCP_PATH_ANY], [test "x$enable_dpcp_rx" = xyes || test "x$enable_dpcp_tx" = xyes])
# DPCP TX or RX or DOCA only
AM_CONDITIONAL([DEFINED_DPCP_PATH_MIX], [test "x$enable_dpcp_rx" != xyes || test "x$enable_dpcp_tx" != xyes])

])
