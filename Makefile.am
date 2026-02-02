SUBDIRS := third_party src tools docs/man


DIST_SUBDIRS := third_party src tests tools docs/man

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

