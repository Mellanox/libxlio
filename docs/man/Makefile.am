xlio_man_pages = \
	xlio.7 \
	xliod.8 \
	xlio_stats.8

man_MANS = $(xlio_man_pages)
CLEANFILES = $(xlio_man_pages)
EXTRA_DIST = \
	$(xlio_man_pages:.7=.7.in) \
	$(xlio_man_pages:.8=.8.in)

%.7: %.7.in
	@cp $< $@
	@sed -i 's/#BUILD_DATE#/@BUILD_DATE@/g' $@
	@sed -i 's/#PRJ_LIBRARY_MAJOR#/@PRJ_LIBRARY_MAJOR@/g' $@
	@sed -i 's/#PRJ_LIBRARY_MINOR#/@PRJ_LIBRARY_MINOR@/g' $@
	@sed -i 's/#PRJ_LIBRARY_REVISION#/@PRJ_LIBRARY_REVISION@/g' $@

%.8: %.8.in
	@cp $< $@
	@sed -i 's/#BUILD_DATE#/@BUILD_DATE@/g' $@
	@sed -i 's/#PRJ_LIBRARY_MAJOR#/@PRJ_LIBRARY_MAJOR@/g' $@
	@sed -i 's/#PRJ_LIBRARY_MINOR#/@PRJ_LIBRARY_MINOR@/g' $@
	@sed -i 's/#PRJ_LIBRARY_REVISION#/@PRJ_LIBRARY_REVISION@/g' $@
