/* 
 *
 * Syslog functions.
 * Copyright (C) 2003, 2004 Mondru AB.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include "system.h"
#include "syserr.h"
#include "radius.h"
#include "md5.h"
#include "dhcp.h"
#include "redir.h"
#include "chilli.h"
#include "options.h"
#include "bstrlib.h"

void sys_err(int pri, char *fn, int ln, int en, const char *fmt, ...) {
  if (pri==LOG_DEBUG && !options()->debug) return;
  {
    bstring bt = bfromcstralloc(128,"");
    int sz;
    
    bvformata(sz, bt, fmt, fmt);
    
    if (options()->foreground && options()->debug) {
      fprintf(stderr, "%s: %d: %d (%s) %s\n", fn, ln, en, en ? strerror(en) : "Debug", bt->data);
    } else {
      if (en)
	syslog(pri, "%s: %d: %d (%s) %s", fn, ln, en, strerror(en), bt->data);
      else
	syslog(pri, "%s: %d: %s", fn, ln, bt->data);
    }
    
    bdestroy(bt);
  }
}

void sys_errpack(int pri, char *fn, int ln, int en, struct sockaddr_in *peer,
		 void *pack, unsigned len, char *fmt, ...) {
  bstring bt = bfromcstr("");
  bstring bt2 = bfromcstr("");
  int sz;
  int n;
  
  bvformata(sz, bt, fmt, fmt);

  bassignformat(bt2, ". Packet from %s:%u, length: %d, content:",
		inet_ntoa(peer->sin_addr),
		ntohs(peer->sin_port),
		len);

  bconcat(bt, bt2);

  for(n=0; n < len; n++) {
    bassignformat(bt, " %02hhx", ((unsigned char*)pack)[n]);
    bconcat(bt, bt2);
  }
  
  if (options()->foreground && options()->debug) {
    fprintf(stderr, "%s: %d: %d (%s) %s", fn, ln, en, strerror(en), bt->data);
  } else {
    if (en)
      syslog(pri, "%s: %d: %d (%s) %s", fn, ln, en, strerror(en), bt->data);
    else
      syslog(pri, "%s: %d: %s", fn, ln, bt->data);
  }

  bdestroy(bt);
  bdestroy(bt2);
}
