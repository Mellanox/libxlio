# opt.m4 - Macros to control optimization
# 
# Copyright (C) Mellanox Technologies Ltd. 2001-2021. ALL RIGHTS RESERVED.
# See file LICENSE for terms.
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
])
