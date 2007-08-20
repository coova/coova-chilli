## Process this file with automake to produce Makefile.in

chillidir = $(sysconfdir)/chilli
chilli_SCRIPTS = wwwsh

wwwdir = $(chillidir)/www
wwwDATAFILES = chillijs.chi chilliform.chi coova.html coova.jpg coova.png \
wait.gif openid.gif ChilliLibrary.js json_html.tmpl 
www_DATA = $(wwwDATAFILES) config.sh

EXTRA_DIST = $(chilli_SCRIPTS) $(wwwDATAFILES) config.sh.in

edit = sed \
	-e 's,@SBINDIR\@,$(sbindir),g' \
	-e 's,@VARRUN\@,$(localstatedir)/run,g' \
	-e 's,@ETCCHILLI\@,$(sysconfdir)/chilli,g' \
	-e 's,@PREFIX\@,$(prefix),g'

config.sh: Makefile config.sh.in
	rm -f config.sh config.sh.tmp
	$(edit) config.sh.in >config.sh.tmp
	mv config.sh.tmp config.sh
