# $Id: Makefile.am,v 1.3 2008/08/04 15:31:07 dembour Exp $
SUBDIRS = $(DIRECTORIES) man
DIST_SUBDIRS = $(DIRECTORIES) man
EXTRA_DIST = doc common

dist-hook:
	rm -rf `find $(distdir)/ -name CVS`

