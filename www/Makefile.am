## Process this file with automake to produce Makefile.in

chillidir = $(sysconfdir)/chilli
chilli_SCRIPTS = wwwsh

wwwdir = $(chillidir)/www

wwwDATAFILES = \
chillijs.chi chillijs.chi.sh chilliform.chi chilliform.chi.sh \
coova.html coova.jpg coova.png wait.gif openid.gif \
ChilliLibrary.js chilliController.js json_html.tmpl 

www_DATA = $(wwwDATAFILES) config.sh

EXTRA_DIST = $(chilli_SCRIPTS) $(wwwDATAFILES) config.sh.in

