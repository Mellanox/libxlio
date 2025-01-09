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

# verbs.m4 - Parsing verbs capabilities
#


# Check attributes
# Usage: CHECK_VERBS_ATTRIBUTE([attribute], [header file], [definition])
# Note:
# - [definition] can be omitted if it is equal to attribute
#
AC_DEFUN([CHECK_VERBS_ATTRIBUTE], [
    AC_LINK_IFELSE([AC_LANG_PROGRAM([
        [#include <$2>]],
        [[int attr = (int)$1; attr = attr;]])],
        [prj_cv_attribute_$1=yes],
        [prj_cv_attribute_$1=no])

    AC_MSG_CHECKING([for attribute $1])
    AC_MSG_RESULT([$prj_cv_attribute_$1])
    AS_IF([test "x$3" != "x"], [prj_cv_attribute_ex_$3=$prj_cv_attribute_$1])
    AS_IF([test "x$prj_cv_attribute_$1" = "xyes"], [
        AS_IF([test "x$3" = "x"],
            [AC_DEFINE_UNQUOTED([DEFINED_$1], [1], [Define to 1 if attribute $1 is supported])],
            [AC_DEFINE_UNQUOTED([DEFINED_$3], [1], [Define to 1 if attribute $1 is supported])]
        )
    ])
])

# Check attributes
# Usage: CHECK_VERBS_MEMBER([attribute], [header file], [definition])
#
AC_DEFUN([CHECK_VERBS_MEMBER], [
    AC_CHECK_MEMBER( $1, [AC_DEFINE_UNQUOTED([DEFINED_$3], [1], [Define to 1 if attribute $1 is supported])], [], [[#include <$2>]])
])

##########################
# Configure ofed capabilities
#
AC_DEFUN([VERBS_CAPABILITY_SETUP],
[

AC_CHECK_HEADERS([infiniband/verbs.h], ,
    [AC_MSG_ERROR([Unable to find the libibverbs-devel header files])])

AC_CHECK_HEADERS([rdma/rdma_cma.h], ,
    [AC_MSG_ERROR([Unable to find the librdmacm-devel header files])])

AC_CHECK_LIB(ibverbs,
    ibv_get_device_list, [VERBS_LIBS="$VERBS_LIBS -libverbs"],
    AC_MSG_ERROR([ibv_get_device_list() not found.]))

AC_CHECK_LIB(rdmacm,
    rdma_create_id, [VERBS_LIBS="$VERBS_LIBS -lrdmacm"],
    AC_MSG_ERROR([rdma_create_id() not found.]))

AC_SUBST([VERBS_LIBS])

# Save LIBS
verbs_saved_libs=$LIBS
LIBS="$LIBS $VERBS_LIBS"


# Check if VERBS version
#
prj_cv_verbs=0
prj_cv_verbs_str="None"
AC_CHECK_HEADER([infiniband/verbs.h],
	[AC_CHECK_MEMBERS([struct ibv_query_device_ex_input.comp_mask],
		[prj_cv_verbs=3 prj_cv_verbs_str="Upstream"],
		[prj_cv_verbs=1 prj_cv_verbs_str="Legacy"],
		[[#include <infiniband/verbs.h>]] )],
		[],
		[AC_MSG_ERROR([Can not detect VERBS version])]
)
AC_MSG_CHECKING([for OFED Verbs version])
AC_MSG_RESULT([$prj_cv_verbs_str])
AC_DEFINE_UNQUOTED([DEFINED_VERBS_VERSION], [$prj_cv_verbs], [Define found Verbs version])


# Check if direct hardware operations can be used instead of VERBS API
#
prj_cv_directverbs=0
case "$prj_cv_verbs" in
    1)
        ;;
    3)
        AC_CHECK_HEADER([infiniband/mlx5dv.h],
            [AC_CHECK_LIB(mlx5,
                mlx5dv_init_obj, [VERBS_LIBS="$VERBS_LIBS -lmlx5" prj_cv_directverbs=$prj_cv_verbs])])
        ;;
    *)
        AC_MSG_ERROR([Unrecognized parameter 'prj_cv_verbs' as $prj_cv_verbs])
        ;;
esac
AC_MSG_CHECKING([for direct verbs support])
if test "$prj_cv_directverbs" -ne 0; then
    AC_DEFINE_UNQUOTED([DEFINED_DIRECT_VERBS], [$prj_cv_directverbs], [Direct VERBS support])
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi


# Check <verbs.h>
#
CHECK_VERBS_ATTRIBUTE([IBV_CQ_ATTR_MODERATE], [infiniband/verbs.h], [IBV_CQ_ATTR_MODERATE])
CHECK_VERBS_ATTRIBUTE([IBV_QPT_RAW_PACKET], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_WC_WITH_VLAN], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_DEVICE_RAW_IP_CSUM], [infiniband/verbs.h])
CHECK_VERBS_ATTRIBUTE([IBV_SEND_IP_CSUM], [infiniband/verbs.h])
#CHECK_VERBS_ATTRIBUTE([IBV_WC_EX_WITH_COMPLETION_TIMESTAMP], [infiniband/verbs.h], [IBV_CQ_TIMESTAMP])
CHECK_VERBS_MEMBER([struct ibv_device_attr_ex.orig_attr], [infiniband/verbs.h], [IBV_DEVICE_ATTR_EX])
CHECK_VERBS_MEMBER([struct ibv_alloc_dm_attr.length], [infiniband/verbs.h], [IBV_DM])
CHECK_VERBS_MEMBER([struct ibv_packet_pacing_caps.qp_rate_limit_min], [infiniband/verbs.h], [IBV_PACKET_PACING_CAPS])
CHECK_VERBS_MEMBER([struct ibv_qp_rate_limit_attr.max_burst_sz], [infiniband/verbs.h], [IBV_QP_SUPPORT_BURST])

# Check Upstream
#
if test "x$prj_cv_verbs" == x3; then
    CHECK_VERBS_ATTRIBUTE([IBV_WR_TSO], [infiniband/verbs.h], [TSO])

    if test "x$prj_cv_directverbs" == x3; then
        CHECK_VERBS_ATTRIBUTE([MLX5_OPCODE_NOP], [infiniband/mlx5dv.h], [IBV_WR_NOP])
        #CHECK_VERBS_MEMBER([struct mlx5dv_clock_info.last_cycles], [infiniband/mlx5dv.h], [IBV_CLOCK_INFO])
        CHECK_VERBS_MEMBER([struct mlx5dv_context.num_lag_ports], [infiniband/mlx5dv.h], [ROCE_LAG])
        CHECK_VERBS_ATTRIBUTE([MLX5DV_QP_MASK_RAW_QP_HANDLES], [infiniband/mlx5dv.h], [DV_RAW_QP_HANDLES])
    fi
fi

# Restore LIBS
LIBS=$verbs_saved_libs
])
