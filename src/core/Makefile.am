
noinst_LTLIBRARIES = \
	libconfig_parser.la
libconfig_parser_la_SOURCES =
BUILT_SOURCES =

AM_LFLAGS = -Plibxlio_yy
AM_YFLAGS = -plibxlio_yy -d
LEX_OUTPUT_ROOT=lex.libxlio_yy

# consider config_scanner.c, config_parser.c, config_parser.h as source (and not
# as built) because we don't want it to be created by old version of flex/yacc
# on some machines that will generate gcc warmings.
# in case you change the *.l or *.y in the future - than change the commenting in the following 3 lines
#
#BUILT_SOURCES += config_scanner.c config_parser.h config_parser.c
#libconfig_parser_la_SOURCES += util/config_scanner.l util/config_parser.y
libconfig_parser_la_SOURCES += config_scanner.c config_parser.c


CLEANFILES = $(BUILT_SOURCES)
dist-hook:
	cd $(distdir); rm -f $(BUILT_SOURCES)

SUBDIRS = infra netlink

EXTRA_DIST = \
	util/libxlio.conf

sysconf_DATA = util/libxlio.conf
otherincludedir = $(includedir)/mellanox
otherinclude_HEADERS = xlio_extra.h \
		       xlio.h

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/libxlio.la
	rm -f $(DESTDIR)$(bindir)/state_machine_test
	rm -f $(DESTDIR)$(bindir)/vlogger_test


uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/libxlio.so*
	rm -f $(DESTDIR)$(libdir)/libxlio.a

lib_LTLIBRARIES = libxlio.la

AM_CPPFLAGS := \
	-I$(top_srcdir)/src ${LIBNL_CFLAGS}

libxlio_la_CFLAGS = $(XLIO_STATIC_BUILD) $(XLIO_LTO) $(XLIO_PROFILE)
libxlio_la_CXXFLAGS = $(XLIO_STATIC_BUILD) $(XLIO_LTO) $(XLIO_PROFILE)

libxlio_la_LDFLAGS := $(XLIO_LTO) $(XLIO_PROFILE) -no-undefined \
	-version-number @PRJ_LIBRARY_MAJOR@:@PRJ_LIBRARY_MINOR@:@PRJ_LIBRARY_REVISION@

libxlio_la_LIBADD = \
	-lrt -ldl -lpthread $(LIBNL_LIBS) $(VERBS_LIBS) $(DPCP_LIBS) $(XLIO_GCOV) \
	$(top_builddir)/src/utils/libutils.la \
	$(top_builddir)/src/vlogger/libvlogger.la \
	$(top_builddir)/src/state_machine/libstate_machine.la \
	$(top_builddir)/src/stats/libstats.la \
	$(top_builddir)/src/core/netlink/libnetlink.la \
	$(top_builddir)/src/core/infra/libinfra.la \
	libconfig_parser.la
	
libxlio_la_SOURCES := \
	dev/allocator.cpp \
	dev/buffer_pool.cpp \
	dev/cq_mgr_rx.cpp \
	dev/cq_mgr_rx_regrq.cpp \
	dev/cq_mgr_rx_strq.cpp \
	dev/cq_mgr_tx.cpp \
	dev/dm_mgr.cpp \
	dev/hw_queue_tx.cpp \
	dev/hw_queue_rx.cpp \
	dev/gro_mgr.cpp \
	dev/rfs.cpp \
	dev/rfs_uc.cpp \
	dev/rfs_uc_tcp_gro.cpp \
	dev/rfs_mc.cpp \
	dev/rfs_rule.cpp \
	dev/time_converter.cpp \
	dev/time_converter_ptp.cpp \
	dev/time_converter_rtc.cpp \
	dev/time_converter_ib_ctx.cpp \
	dev/ib_ctx_handler.cpp \
	dev/ib_ctx_handler_collection.cpp \
	dev/net_device_val.cpp \
	dev/net_device_entry.cpp \
	dev/net_device_table_mgr.cpp \
	dev/wqe_send_handler.cpp \
	dev/src_addr_selector.cpp \
	dev/ring.cpp \
	dev/ring_bond.cpp \
	dev/ring_slave.cpp \
	dev/ring_simple.cpp \
	dev/ring_tap.cpp \
	dev/ring_allocation_logic.cpp \
	\
	event/delta_timer.cpp \
	event/event_handler_manager.cpp \
	event/event_handler_manager_local.cpp \
	event/poll_group.cpp \
	event/vlogger_timer_handler.cpp \
	event/netlink_event.cpp \
	\
	ib/base/verbs_extra.cpp \
	ib/mlx5/ib_mlx5.cpp \
	ib/mlx5/ib_mlx5_dv.cpp \
	\
	iomux/epfd_info.cpp \
	iomux/epoll_wait_call.cpp \
	iomux/io_mux_call.cpp \
	iomux/poll_call.cpp \
	iomux/select_call.cpp \
	\
	lwip/pbuf.c \
	lwip/tcp.c \
	lwip/tcp_in.c \
	lwip/tcp_out.c \
	lwip/cc.c \
	lwip/cc_lwip.c \
	lwip/cc_cubic.c \
	lwip/cc_none.c \
	\
	proto/ip_frag.cpp \
	proto/flow_tuple.cpp \
	proto/xlio_lwip.cpp \
	proto/neighbour.cpp \
	proto/neighbour_table_mgr.cpp \
	proto/netlink_socket_mgr.cpp \
	proto/L2_address.cpp \
	proto/mem_desc.cpp \
	proto/mapping.cpp \
	proto/route_table_mgr.cpp \
	proto/route_entry.cpp \
	proto/route_val.cpp \
	proto/rule_table_mgr.cpp \
	proto/rule_entry.cpp \
	proto/rule_val.cpp \
	proto/dst_entry.cpp \
	proto/dst_entry_udp.cpp \
	proto/dst_entry_udp_mc.cpp \
	proto/dst_entry_tcp.cpp \
	proto/header.cpp \
	proto/arp.cpp \
	\
	sock/sockinfo.cpp \
	sock/sockinfo_udp.cpp \
	sock/sockinfo_ulp.cpp \
	sock/sockinfo_tcp.cpp \
	sock/tcp_seg_pool.cpp \
	sock/fd_collection.cpp \
	sock/sock-redirect.cpp \
	sock/sock-app.cpp \
	sock/sock-extra.cpp \
	sock/sockinfo_nvme.cpp \
	sock/bind_no_port.cpp \
	\
	util/hugepage_mgr.cpp \
	util/wakeup.cpp \
	util/wakeup_pipe.cpp \
	util/match.cpp \
	util/utils.cpp \
	util/instrumentation.cpp \
	util/sys_vars.cpp \
	util/agent.cpp \
	util/data_updater.cpp \
	\
	libxlio.c \
	main.cpp \
	\
	dev/allocator.h \
	dev/buffer_pool.h \
	dev/cq_mgr_rx.h \
	dev/cq_mgr_rx_inl.h \
	dev/cq_mgr_rx_regrq.h \
	dev/cq_mgr_rx_strq.h \
	dev/cq_mgr_tx.h \
	dev/dm_mgr.h \
	dev/gro_mgr.h \
	dev/ib_ctx_handler_collection.h \
	dev/ib_ctx_handler.h \
	dev/time_converter.h \
	dev/time_converter_ptp.h \
	dev/time_converter_rtc.h \
	dev/time_converter_ib_ctx.h \
	dev/net_device_entry.h \
	dev/net_device_table_mgr.h \
	dev/net_device_val.h \
	dev/hw_queue_rx.h \
	dev/hw_queue_tx.h \
	dev/rfs.h \
	dev/rfs_mc.h \
	dev/rfs_uc.h \
	dev/rfs_uc_tcp_gro.h \
	dev/rfs_rule.h \
	dev/src_addr_selector.h \
	dev/ring.h \
	dev/ring_bond.h \
	dev/ring_slave.h \
	dev/ring_simple.h \
	dev/ring_tap.h \
	dev/ring_allocation_logic.h \
	dev/wqe_send_handler.h \
	dev/xlio_ti.h \
	\
	event/command.h \
	event/delta_timer.h \
	event/event.h \
	event/event_handler_ibverbs.h \
	event/event_handler_manager.h \
	event/event_handler_manager_local.h \
	event/event_handler_rdma_cm.h \
	event/netlink_event.h \
	event/poll_group.h \
	event/timer_handler.h \
	event/vlogger_timer_handler.h \
	\
	ib/base/verbs_extra.h \
	ib/mlx5/ib_mlx5.h \
	\
	infra/sender.h \
	infra/subject_observer.h \
	infra/cache_subject_observer.h \
	\
	iomux/epfd_info.h \
	iomux/epoll_wait_call.h \
	iomux/io_mux_call.h \
	iomux/poll_call.h \
	iomux/select_call.h \
	\
	lwip/cc_cubic.h \
	lwip/cc.h \
	lwip/def.h \
	lwip/err.h \
	lwip/ip_addr.h \
	lwip/opt.h \
	lwip/pbuf.h \
	lwip/tcp.h \
	lwip/tcp_impl.h \
	\
	netlink/link_info.h \
	netlink/neigh_info.h \
	netlink/netlink_wrapper.h \
	netlink/route_info.h \
	\
	proto/arp.h \
	proto/mem_desc.h \
	proto/dst_entry.h \
	proto/dst_entry_tcp.h \
	proto/dst_entry_udp.h \
	proto/dst_entry_udp_mc.h \
	proto/flow_tuple.h \
	proto/header.h \
	proto/ip_frag.h \
	proto/L2_address.h \
	proto/mapping.h \
	proto/mem_buf_desc.h \
	proto/neighbour.h \
	proto/neighbour_table_mgr.h \
	proto/netlink_socket_mgr.h \
	proto/route_entry.h \
	proto/route_rule_table_key.h \
	proto/route_table_mgr.h \
	proto/route_val.h \
	proto/rule_entry.h \
	proto/rule_table_mgr.h \
	proto/rule_val.h \
	proto/tls.h \
	proto/xlio_lwip.h \
	proto/nvme_parse_input_args.h \
	\
	sock/cleanable_obj.h \
	sock/fd_collection.h \
	sock/sockinfo.h \
	sock/sockinfo_tcp.h \
	sock/sockinfo_udp.h \
	sock/sockinfo_ulp.h \
	sock/tcp_seg_pool.h \
	sock/sock-redirect.h \
	sock/sock-redirect-internal.h \
	sock/sock-app.h \
	sock/sock-extra.h \
	sock/sockinfo_nvme.h \
	sock/bind_no_port.h \
	\
	util/chunk_list.h \
	util/hugepage_mgr.h \
	util/if.h \
	util/instrumentation.h \
	util/libxlio.h \
	util/list.h \
	util/sg_array.h \
	util/ip_address.h \
	util/sock_addr.h \
	util/sysctl_reader.h \
	util/sys_vars.h \
	util/to_str.h \
	util/utils.h \
	util/valgrind.h \
	util/xlio_list.h \
	util/xlio_stats.h \
	util/vtypes.h \
	util/wakeup.h \
	util/wakeup_pipe.h \
	util/agent.h \
	util/agent_def.h \
	util/data_updater.h \
	\
	config_parser.h \
	main.h \
	xlio_extra.h

libxlio_la_DEPENDENCIES = \
	$(top_builddir)/src/vlogger/libvlogger.la \
	$(top_builddir)/src/state_machine/libstate_machine.la \
	$(top_builddir)/src/stats/libstats.la \
	$(top_builddir)/src/core/netlink/libnetlink.la \
	$(top_builddir)/src/core/infra/libinfra.la \
	libconfig_parser.la

