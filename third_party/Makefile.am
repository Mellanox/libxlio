SUBDIRS = json-c 

# Ensure json-c is configured before make runs
all-recursive: json-c-configure

json-c-configure:
	cd $(srcdir)/json-c && \
	if [ ! -f Makefile ]; then \
		./configure; \
	fi

.PHONY: json-c-configure 