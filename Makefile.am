SUBDIRS := third_party src tools docs/man
DIST_SUBDIRS := third_party src tests tools docs/man

# Build and install dpcp only if it is the built-in one.
# So we do not put submodules/libdpcp in SUBDIRS, instead we do this:
if BUILD_BUILTIN_DPCP

# BUILT_SOURCES are built before anything else
BUILT_SOURCES = .libdpcp-installed
CLEANFILES = .libdpcp-installed

LIBDPCP_DIR = $(top_builddir)/submodules/libdpcp

.libdpcp-installed:
	@test -f "$(LIBDPCP_DIR)/Makefile" || { echo "Error: libdpcp submodule at $(LIBDPCP_DIR) not configured."; exit 1; }
	$(MAKE) -C "$(LIBDPCP_DIR)"
	$(MAKE) -C "$(LIBDPCP_DIR)" install
	touch $@

clean-local:
	-$(MAKE) -C "$(LIBDPCP_DIR)" clean 2>/dev/null || true
	rm -f .libdpcp-installed

distclean-local:
	-$(MAKE) -C "$(LIBDPCP_DIR)" distclean 2>/dev/null || true

endif  # of BUILD_BUILTIN_DPCP

noinst_SCRIPTS = \
	$(wildcard contrib/scripts/*)

EXTRA_DIST = \
	contrib \
	debian \
	LICENSE \
	CHANGES \
	README


.PHONY: tests

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README CHANGES

install-exec-hook:
	if command -v systemctl >/dev/null 2>&1; then \
		mkdir -p $(DESTDIR)$(prefix)/lib/systemd/system/; \
		cp $(top_builddir)/contrib/scripts/xlio.service $(DESTDIR)$(prefix)/lib/systemd/system/xlio.service; \
		chmod 644 $(DESTDIR)$(prefix)/lib/systemd/system/xlio.service; \
	fi

uninstall-hook:
	if command -v systemctl >/dev/null 2>&1; then \
		rm -rf $(DESTDIR)$(prefix)/lib/systemd/system/xlio.service; \
	fi

install-all: install

uninstall-all: uninstall

tests:
	$(MAKE)
	$(MAKE) -C tests/gtest
	$(MAKE) -C tests/unit_tests
	$(MAKE) -C tests/latency_test
	$(MAKE) -C tests/throughput_test
	$(MAKE) -C tests/pps_test

demo:
	$(MAKE)
	$(MAKE) -C src/core/infra

