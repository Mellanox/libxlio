noinst_PROGRAMS = gtest

# google test shows some warnings that are suppressed
AM_CXXFLAGS = \
	-Wno-error=sign-compare \
	-Wno-error=missing-field-initializers \
	-g -O3 -std=c++11

AM_CPPFLAGS = \
	-DGTEST_LANG_CXX11=1 \
	-DGTEST_HAS_PTHREAD=1 \
	-DGTEST_USE_OWN_TR1_TUPLE=0 \
	-DGTEST_HAS_TR1_TUPLE=0 \
	-DGTEST_ENV_HAS_STD_TUPLE_=1 \
	-DGTEST_USES_SIMPLE_RE=0 \
	-DGTEST_HAS_COMBINE=0 \
	-DPTHREADS \
	\
	-DGTEST_DONT_DEFINE_ASSERT_GT=0 \
	-DGTEST_DONT_DEFINE_ASSERT_GE=0 \
	-DGTEST_DONT_DEFINE_ASSERT_LT=0 \
	-DGTEST_DONT_DEFINE_ASSERT_LE=0 \
	-DGTEST_DONT_DEFINE_ASSERT_NE=0 \
	-DGTEST_DONT_DEFINE_ASSERT_EQ=0 \
	-DGTEST_DONT_DEFINE_SUCCEED=0 \
	-DGTEST_DONT_DEFINE_FAIL=0 \
	-DGTEST_DONT_DEFINE_TEST=0 \
	\
	-DGTEST_HAS_STD_WSTRING=0 \
	-DGTEST_HAS_GLOBAL_STRING=0 \
	\
	-DGTEST_OS_WINDOWS=0 \
	-DGTEST_OS_LINUX_ANDROID=0 \
	-DGTEST_OS_CYGWIN=0 \
	-DGTEST_OS_SOLARIS=0 \
	-DGTEST_OS_SYMBIAN=0 \
	-DGTEST_OS_WINDOWS_MOBILE=0 \
	-DGTEST_OS_QNX=0 \
	-DGTEST_OS_MAC=0 \
	-DGTEST_OS_IOS=0 \
	-DGTEST_OS_ZOS



# lgtest
noinst_LTLIBRARIES = libgtest.la

libgtest_la_CPPFLAGS = \
	-I$(top_srcdir)/tests/gtest/googletest \
	-I$(top_srcdir)/tests/gtest/googletest/include \
	$(AM_CPPFLAGS)

libgtest_la_LDFLAGS = -pthread -static
libgtest_la_CXXFLAGS = \
	$(AM_CXXFLAGS)

EXTRA_DIST = \
	googletest/include \
	googletest/src \
	googletest/README.md \
	googletest/LICENSE

libgtest_la_SOURCES = \
	googletest/src/gtest-all.cc \
	googletest/src/gtest_main.cc

# gtest
gtest_LDADD = libgtest.la  $(VERBS_LIBS)

gtest_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	-I$(top_srcdir)/tests/gtest \
	-I$(top_srcdir)/tests/gtest/googletest/include \
	$(AM_CPPFLAGS)

gtest_LDFLAGS = -no-install
gtest_CXXFLAGS = \
	$(AM_CXXFLAGS)

gtest_SOURCES = \
	main.cc \
	\
	common/sys.cc \
	\
	common/base.cc \
	\
	sock/sock_base.cc \
	sock/sock_socket.cc \
	\
	mix/mix_base.cc \
	mix/sg_array.cc \
	mix/sock_addr.cc \
	mix/ip_address.cc \
	mix/mix_list.cc \
	\
	tcp/tcp_accept.cc \
	tcp/tcp_bind.cc \
	tcp/tcp_connect.cc \
	tcp/tcp_connect_nb.cc \
	tcp/tcp_event.cc \
	tcp/tcp_rfs.cc \
	tcp/tcp_send.cc \
	tcp/tcp_sendto.cc \
	tcp/tcp_sendfile.cc \
	tcp/tcp_send_zc.cc \
	tcp/tcp_socket.cc \
	tcp/tcp_sockopt.cc \
	tcp/tcp_tls.cc \
	\
	udp/udp_socket.cc \
	udp/udp_bind.cc \
	udp/udp_connect.cc \
	udp/udp_recv.cc \
	udp/udp_send.cc \
	udp/udp_sendto.cc \
	udp/udp_rfs.cc \
	\
	core/xlio_base.cc \
	core/xlio_sockopt.cc \
	core/xlio_send_zc.cc \
	core/xlio_ioctl.cc \
	\
	extra_api/extra_ring.cc \
	extra_api/extra_poll.cc \
	\
	nvme/nvme.cc \
	\
	xliod/xliod_base.cc \
	xliod/xliod_bitmap.cc \
	xliod/xliod_hash.cc \
	xliod/xliod_init.cc \
	xliod/xliod_state.cc \
	xliod/xliod_flow.cc

noinst_HEADERS = \
	common/tap.h \
	common/def.h \
	common/sys.h \
	common/log.h \
	common/cmn.h \
	\
	common/base.h \
	\
	sock/sock_base.h \
	\
	mix/mix_base.h \
	\
	tcp/tcp_base.h \
	\
	udp/udp_base.h \
	\
	core/xlio_base.h \
	\
	xliod/xliod_base.h

gtest_DEPENDENCIES = \
	libgtest.la

# This workaround allows to compile files located
# at another directory.
# This place resolve make distcheck isue
nodist_gtest_SOURCES = \
	hash.c

CLEANFILES = hash.c

hash.c:
	@echo "#include \"$(top_builddir)/tools/daemon/$@\"" >$@

