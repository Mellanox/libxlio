sbin_PROGRAMS = xliod

xliod_LDADD = $(DOCA_LIBS)

xliod_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core

xliod_LDFLAGS  = 
xliod_CFLAGS = -Wno-deprecated-declarations

xliod_SOURCES = \
	daemon.c \
	loop.c \
	hash.c \
	store.c \
	message.c \
	notify.c

noinst_HEADERS = \
	daemon.h \
	hash.h \
	bitmap.h
