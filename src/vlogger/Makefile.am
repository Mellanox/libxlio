AM_CPPFLAGS := -I$(top_srcdir)/src 

noinst_LTLIBRARIES = libvlogger.la
libvlogger_la_LDFLAGS = -static
libvlogger_la_LIBADD = -lrt -ldoca_common
libvlogger_la_SOURCES = vlogger.cpp vlogger.h

noinst_PROGRAMS = vlogger_test
vlogger_test_LDADD = \
	$(top_builddir)/src/utils/libutils.la \
	libvlogger.la \
	$(DOCA_LIBS)
vlogger_test_SOURCES = main.cpp
