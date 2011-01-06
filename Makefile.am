## Process this file with automake to produce Makefile.in
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = bstring src doc www conf debian distro
EXTRA_DIST = CREDITS 
if WITH_MINIPORTAL
SUBDIRS += miniportal
endif
if WITH_JSONLIB
SUBDIRS += json
endif
