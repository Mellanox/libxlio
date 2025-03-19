#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#

# utls.m4 - TLS offload support
#

##########################
# UTLS acceleration support
#
AC_DEFUN([UTLS_CAPABILITY_SETUP],
[
AC_ARG_ENABLE([utls],
    AS_HELP_STRING([--enable-utls],
                   [Enable UTLS acceleration support (default=auto)]),
    [],
    [enable_utls=auto]
)

prj_cv_dpcp_1_1_44=0
AS_IF([test "$prj_cv_dpcp" -ne 0],
    [
    AC_LANG_PUSH([C++])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <mellanox/dpcp.h>]],
         [[dpcp::tis* _tis;
           dpcp::tls_dek* _dek;
           int tis_bit = (int)dpcp::TIS_ATTR_TLS;
           (void)_tis; (void)_dek;
           (void)tis_bit;]])],
         [prj_cv_dpcp_1_1_44=1])
    AC_LANG_POP()
    ])

AS_IF([test "$prj_cv_dpcp_1_1_44" -eq 0],
    [
    AS_IF([test "x$enable_utls" == xauto],
        [enable_utls=no])
    AS_IF([test "x$enable_utls" == xyes],
        [
        AC_MSG_CHECKING([for utls support])
        AC_MSG_ERROR([utls requires dpcp 1.1.44 or later, see --with-dpcp])
        ])
    ])

prj_cv_utls=0
AS_IF([test "x$enable_utls" != xno],
    [
    AC_CHECK_HEADER(
        [linux/tls.h],
        [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <linux/tls.h>]],
             [[int flag = TLS_TX;
               (void)flag;]])],
             [prj_cv_utls=1])
        ])
    ])

prj_cv_utls_aes256=0
AS_IF([test "$prj_cv_utls" -ne 0],
    [
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <linux/tls.h>]],
         [[struct tls12_crypto_info_aes_gcm_256 crypto_info;
           char arr[TLS_CIPHER_AES_GCM_256_KEY_SIZE];
           crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
           (void)crypto_info; (void)arr;]])],
         [prj_cv_utls_aes256=1])
    ])

AC_CHECK_HEADER(
    [openssl/evp.h], [],
    # Currently, we don't support TX without RX, so disable UTLS completely
    [prj_cv_utls=0])

AC_MSG_CHECKING([for utls support])
if test "$prj_cv_utls" -ne 0; then
    AC_DEFINE_UNQUOTED([DEFINED_UTLS], [1], [Define to 1 to enable UTLS])
    AC_MSG_RESULT([yes])

    AC_MSG_CHECKING([for utls AES-256 support])
    if test "$prj_cv_utls" -ne 0; then
        AC_DEFINE_UNQUOTED([DEFINED_UTLS_AES256], [1], [Define to 1 to enable UTLS AES-256])
        AC_MSG_RESULT([yes])
    else
        AC_MSG_RESULT([no])
    fi
else
    AS_IF([test "x$enable_utls" == xyes],
        [AC_MSG_ERROR([utls support requested but kTLS or openssl not found])],
        [AC_MSG_RESULT([no])])
fi
])
