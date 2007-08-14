## Process this file with automake to produce Makefile.in

sysconf_DATA = chilli.conf 

chillidir = $(sysconfdir)/chilli
chilli_SCRIPTS = functions up.sh down.sh
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

up.sh: Makefile up.sh.in
	rm -f up.sh up.sh.tmp
	$(edit) up.sh.in >up.sh.tmp
	mv up.sh.tmp up.sh

down.sh: Makefile down.sh.in
	rm -f down.sh down.sh.tmp
	$(edit) down.sh.in >down.sh.tmp
	mv down.sh.tmp down.sh

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

