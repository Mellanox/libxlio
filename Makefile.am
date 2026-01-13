SUBDIRS := third_party src tools docs/man
DIST_SUBDIRS := third_party src tests tools docs/man

.PHONY: tests libdpcp-install

# Build and install dpcp only if it is the built-in one.
# So we do not put submodules/libdpcp in SUBDIRS, instead we do this:
if BUILD_BUILTIN_DPCP

# Invoke CMake before every build and let it decide whether DPCP is up to date.
BUILT_SOURCES = libdpcp-install

if BUILTIN_DPCP_STATIC
DPCP_INSTALL_ARTIFACT = $(DPCP_INSTALL_DIR)/lib/libdpcp.a
else
DPCP_INSTALL_ARTIFACT = $(DPCP_INSTALL_DIR)/lib/libdpcp.so
endif
DPCP_INSTALL_HEADER = $(DPCP_INSTALL_DIR)/include/mellanox/dpcp.h

libdpcp-install:
	@test -f "$(DPCP_BUILD_DIR)/CMakeCache.txt" || { echo "Error: libdpcp at $(DPCP_BUILD_DIR) is not configured."; exit 1; }
	+$(CMAKE) --build "$(DPCP_BUILD_DIR)" --target dpcp
	cd "$(DPCP_BUILD_DIR)" && DESTDIR= $(CMAKE) \
		"-DCMAKE_INSTALL_PREFIX=$(DPCP_INSTALL_DIR)" -P cmake_install.cmake
if BUILTIN_DPCP_STATIC
	$(MKDIR_P) "$(DPCP_INSTALL_DIR)/lib"
	cmp -s "$(DPCP_BUILD_DIR)/libdpcp.a" "$(DPCP_INSTALL_DIR)/lib/libdpcp.a" || \
		cp -f "$(DPCP_BUILD_DIR)/libdpcp.a" "$(DPCP_INSTALL_DIR)/lib/libdpcp.a"
endif
	@test -e "$(DPCP_INSTALL_ARTIFACT)" || { echo "Error: libdpcp library was not installed."; exit 1; }
	@test -f "$(DPCP_INSTALL_HEADER)" || { echo "Error: libdpcp headers were not installed."; exit 1; }

clean-local:
	@if test -f "$(DPCP_BUILD_DIR)/CMakeCache.txt"; then \
		$(CMAKE) --build "$(DPCP_BUILD_DIR)" --target clean; \
	fi
	rm -rf "$(DPCP_INSTALL_DIR)"

if DPCP_CMAKE_IN_SOURCE
distclean-local:
	find "$(DPCP_SOURCE_DIR)" -type d -name CMakeFiles -prune -exec rm -rf {} \;
	find "$(DPCP_SOURCE_DIR)" -type f \
		\( -name CMakeCache.txt -o -name cmake_install.cmake -o -name install_manifest.txt \) -delete
	find "$(DPCP_SOURCE_DIR)" -type f -name Makefile \
		! -path "$(DPCP_SOURCE_DIR)/.ci/Makefile" -delete
	rm -rf "$(DPCP_SOURCE_DIR)/install" "$(DPCP_SOURCE_DIR)/mock_include"
else
distclean-local:
	rm -rf "$(DPCP_BUILD_DIR)"
	rm -rf "$(DPCP_SOURCE_DIR)/src/api/CMakeFiles"
	rm -f "$(DPCP_SOURCE_DIR)/src/api/Makefile" \
		"$(DPCP_SOURCE_DIR)/src/api/cmake_install.cmake"
endif

endif  # of BUILD_BUILTIN_DPCP

DPCP_DIST_SOURCE_DIR = $(abs_top_srcdir)/submodules/libdpcp

dist-hook:
	rm -rf "$(distdir)/submodules/libdpcp"
	$(MKDIR_P) "$(distdir)/submodules/libdpcp"
	@dpcp_git_root=`git -C "$(DPCP_DIST_SOURCE_DIR)" rev-parse --show-toplevel 2>/dev/null || true`; \
	if test "x$$dpcp_git_root" = "x$(DPCP_DIST_SOURCE_DIR)"; then \
		git -C "$(DPCP_DIST_SOURCE_DIR)" archive --format=tar HEAD | \
			tar -xf - -C "$(distdir)/submodules/libdpcp"; \
	else \
		cp -fpR "$(DPCP_DIST_SOURCE_DIR)/." "$(distdir)/submodules/libdpcp"; \
		rm -f "$(distdir)/submodules/libdpcp/.git"; \
		rm -rf "$(distdir)/submodules/libdpcp/build" \
			"$(distdir)/submodules/libdpcp/install" \
			"$(distdir)/submodules/libdpcp/mock_include"; \
		find "$(distdir)/submodules/libdpcp" -type d -name CMakeFiles \
			-prune -exec rm -rf {} \;; \
		find "$(distdir)/submodules/libdpcp" -type f \
			\( -name CMakeCache.txt -o -name cmake_install.cmake -o -name install_manifest.txt \) -delete; \
		find "$(distdir)/submodules/libdpcp" -type f -name Makefile \
			! -path "$(distdir)/submodules/libdpcp/.ci/Makefile" -delete; \
	fi

noinst_SCRIPTS = \
	$(wildcard contrib/scripts/*)

EXTRA_DIST = \
	contrib \
	debian \
	LICENSE \
	CHANGES \
	README

mydocdir = $(if $(docdir),$(docdir),${datadir}/doc/$(distdir))
mydoc_DATA = README CHANGES

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

