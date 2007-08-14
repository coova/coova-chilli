## Process this file with automake to produce Makefile.in

chillidir = $(sysconfdir)/chilli
chilli_SCRIPTS = wwwsh

wwwdir = $(chillidir)/www
www_DATA = chillijs.chi chilliform.chi coova.html coova.jpg coova.png wait.gif \
ChilliLibrary.js json_html.tmpl config.sh

edit = sed \
	-e 's,@SBINDIR\@,$(sbindir),g' \
	-e 's,@VARRUN\@,$(localstatedir)/run,g' \
	-e 's,@ETCCHILLI\@,$(sysconfdir)/chilli,g' \
	-e 's,@PREFIX\@,$(prefix),g'

config.sh: Makefile config.sh.in
	rm -f config.sh config.sh.tmp
	$(edit) config.sh.in >config.sh.tmp
	mv config.sh.tmp config.sh
