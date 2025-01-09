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

# doca.m4 - DOCA Libraries
#

##########################
# DOCA usage support
#
AC_DEFUN([DOCA_CAPABILITY_SETUP],
[

get_version_number_raw_doca()
{
    doca_cv_token=`grep DOCA_VERSION_STRING "${with_doca}/include/doca_version.h" | sed -n 's/^.*\([[0-9]]\+\.[[0-9]]\+\.[[0-9]]\+\).*$/\1/p' `
    echo $doca_cv_token
}

get_version_number_doca()
{
    doca_cv_token=`grep DOCA_VERSION_STRING "${with_doca}/include/doca_version.h" | sed -n 's/^.*\([[0-9]]\+\.[[0-9]]\+\.[[0-9]]\+\).*$/\1/p' `

    if egrep '^[[0-9]]+\.[[0-9]]+\.[[0-9]]+' <<<"$doca_cv_token" >/dev/null 2>&1 ; then
        # It has the correct syntax.
        n=${doca_cv_token//[[!0-9]]/ }
        v=(${n//\./ })

        # DOCA vesrion string parts may have leading zeros such as 2.9.0029
        # A string such as '0029' cannot be used as a number.
        echo "$((${v[[0]]} * 1000000 + ${v[[1]]} * 10000 + $(expr ${v[[2]]} + 0)))"
    else
        echo 0
    fi
}

get_min_supported_version_doca()
{
    echo 2100045
}

AC_ARG_WITH([doca],
    AS_HELP_STRING([--with-doca@<:@=DIR@:>@],
                   [Search for DOCA headers and libraries in DIR @<:@default: /opt/mellanox/doca@:>@]),
    [],
    []
)

prj_cv_doca=0
if test -z "$with_doca" || test "$with_doca" = "yes"; then
    with_doca=/opt/mellanox/doca
fi

if test -d "$with_doca/lib/aarch64-linux-gnu"; then
    prj_cv_doca_LDFLAGS_arch="aarch64-linux-gnu"
fi

if test -d "$with_doca/lib/x86_64-linux-gnu"; then
    prj_cv_doca_LDFLAGS_arch="x86_64-linux-gnu"
fi

FUNC_CHECK_WITHDIR([doca], [$with_doca], [include/doca_version.h])

prj_cv_doca_save_CPPFLAGS="$CPPFLAGS"
prj_cv_doca_save_CXXFLAGS="$CXXFLAGS"
prj_cv_doca_save_CFLAGS="$CFLAGS"
prj_cv_doca_save_LDFLAGS="$LDFLAGS"
prj_cv_doca_save_LIBS="$LIBS"

prj_cv_doca_CPPFLAGS="-I$with_doca/include"
prj_cv_doca_LIBS="-ldoca_common -ldoca_eth -ldoca_flow"
prj_cv_doca_LDFLAGS="-L$with_doca/lib/$prj_cv_doca_LDFLAGS_arch -Wl,--rpath,$with_doca/lib/$prj_cv_doca_LDFLAGS_arch"

CPPFLAGS="$prj_cv_doca_CPPFLAGS $CPPFLAGS"
LDFLAGS="$prj_cv_doca_LDFLAGS $LDFLAGS"
LIBS="$prj_cv_doca_LIBS $LIBS"

AC_LANG_PUSH([C++])
AC_CHECK_HEADER(
    [doca_version.h],
    [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <doca_version.h>]],
            [[doca_version();]])],
            [prj_cv_doca=1])
    ])
AC_LANG_POP()

CPPFLAGS="$prj_cv_doca_save_CPPFLAGS"
CXXFLAGS="$prj_cv_doca_save_CXXFLAGS"
CFLAGS="$prj_cv_doca_save_CFLAGS"
LDFLAGS="$prj_cv_doca_save_LDFLAGS"
LIBS="$prj_cv_doca_save_LIBS"


AC_MSG_CHECKING([for doca support])
if test "$prj_cv_doca" -ne 0; then
    CPPFLAGS="$CPPFLAGS $prj_cv_doca_CPPFLAGS"
    LDFLAGS="$prj_cv_doca_LDFLAGS $LDFLAGS"
    AC_SUBST([DOCA_LIBS], ["-ldoca_common -ldoca_eth -ldoca_flow"])
    doca_version_number_raw=($(get_version_number_raw_doca))
    doca_version_number=($(get_version_number_doca))
    min_supported_version_doca=($(get_min_supported_version_doca))

    if test "$doca_version_number" -ge "$min_supported_version_doca"; then
        AC_DEFINE_UNQUOTED([DEFINED_DOCA_MIN], [$min_supported_version_doca], [Define to DOCA version number (major * 10000 + minor * 100 + patch)])
        AC_MSG_RESULT([yes ($doca_version_number_raw)])
    else
        AC_MSG_ERROR([found incompatible DOCA version $doca_version_number (min supported version $min_supported_version_doca) ])
    fi
else
    AC_MSG_ERROR([DOCA support requested but not present])
fi
])
