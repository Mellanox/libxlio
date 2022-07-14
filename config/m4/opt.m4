#
# Copyright © 2001-2022 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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

# opt.m4 - Macros to control optimization
# 

##########################
# Logging control
#
# VMA defined log levels
#
AC_DEFUN([OPT_CAPABILITY_SETUP],
[
AC_DEFINE(DEFINED_VLOG_INIT,       -2, Log Init Definition)
AC_DEFINE(DEFINED_VLOG_NONE,       -1, Log None Definition)
AC_DEFINE(DEFINED_VLOG_PANIC,       0, Log Panic Definition)
AC_DEFINE(DEFINED_VLOG_ERROR,       1, Log Error Definition)
AC_DEFINE(DEFINED_VLOG_WARNING,     2, Log Warning Definition)
AC_DEFINE(DEFINED_VLOG_INFO,        3, Log Info Definition)
AC_DEFINE(DEFINED_VLOG_DETAILS,     4, Log Details Definition)
AC_DEFINE(DEFINED_VLOG_DEBUG,       5, Log Debug Definition)
AC_DEFINE(DEFINED_VLOG_FINE,        6, Log Fine Definition)
AC_DEFINE(DEFINED_VLOG_FINER,       7, Log Finer Definition)
AC_DEFINE(DEFINED_VLOG_ALL,         8, Log All Definition)

AC_ARG_ENABLE([opt-log],
    AS_HELP_STRING([--enable-opt-log],
        [Optimize latency (none, medium, high) by limiting max log level (default=medium)]),,
    enableval=medium)
AC_MSG_CHECKING([for logging optimization])
enable_opt_log=DEFINED_VLOG_ALL
case "$enableval" in
    no | none)
        ;;
    yes | medium)
        enable_opt_log=DEFINED_VLOG_DEBUG
        ;;
    high)
        enable_opt_log=DEFINED_VLOG_DETAILS
        ;;
    *)
        AC_MSG_ERROR([Unrecognized --enable-opt-log parameter as $enableval])
        ;;
esac
AC_DEFINE_UNQUOTED([MAX_DEFINED_LOG_LEVEL], [$enable_opt_log], [Log optimization level])
AC_MSG_RESULT([$enableval])

##########################
# Force TX Polling control
#
# Polling TX is needed to get completions for send operations.
# - It is important in case TX ZEROCOPY usage.
# - For scenario w/o TX ZEROCOPY forcing this is not mandatory but
#   can impact on final performance.
#
AC_DEFINE_UNQUOTED([DEFINED_FORCE_TX_POLLING], [1], [Define to 1 to force TX Polling])
])
