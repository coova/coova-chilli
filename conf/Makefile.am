## Process this file with automake to produce Makefile.in

sysconf_DATA = chilli.conf 

chillidir = $(sysconfdir)/chilli
chilli_SCRIPTS = firewall functions
chilli_DATA = defaults 

initdir = $(sysconfdir)/init.d
init_SCRIPTS = chilli

edit = sed \
	-e 's,@SBINDIR\@,$(sbindir),g' \
	-e 's,@INITDIR\@,$(sysconfdir)/init.d,g' \
	-e 's,@VARRUN\@,$(localstatedir)/run,g' \
	-e 's,@ETCCHILLI\@,$(sysconfdir)/chilli,g' \
	-e 's,@SYSCONFDIR\@,$(sysconfdir),g' \
	-e 's,@PREFIX\@,$(prefix),g'

functions: Makefile functions.in
	rm -f functions functions.tmp
	$(edit) functions.in >functions.tmp
	mv functions.tmp functions

firewall: Makefile firewall.in
	rm -f firewall firewall.tmp
	$(edit) firewall.in >firewall.tmp
	mv firewall.tmp firewall

chilli: Makefile chilli.in
	rm -f chilli chilli.tmp
	$(edit) chilli.in >chilli.tmp
	chmod +x chilli.tmp
	mv chilli.tmp chilli

chilli.conf: Makefile chilli.conf.in
	rm -f chilli.conf chilli.conf.tmp
	$(edit) chilli.conf.in >chilli.conf.tmp
	mv chilli.conf.tmp chilli.conf

defaults: Makefile defaults.in
	rm -f defaults defaults.tmp
	$(edit) defaults.in >defaults.tmp
	mv defaults.tmp defaults

