/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include "system.h"
#include "ippool.h"
#include "radius.h"
#include "radius_wispr.h"
#include "radius_chillispot.h"
#include "redir.h"
#include "syserr.h"
#include "dhcp.h"
#include "cmdline.h"
#include "chilli.h"
#include "options.h"

int pass_through_add(pass_through *ptlist, size_t ptlen, size_t *ptcnt, pass_through *pt) {
  size_t cnt = *ptcnt;
  int i;

  if (cnt >= ptlen) {
    if (options.debug) 
      log_dbg("No more room for walled garden entries");
    return -1;
  }

  for (i=0; i < cnt; i++) {
    if (!memcmp(&ptlist[i],pt,sizeof(pass_through))) {
      if (options.debug) 
	log_dbg("Uamallowed already exists #%d:%d: proto=%d host=%s port=%d", i, ptlen,
		pt->proto, inet_ntoa(pt->host), pt->port);
      return 0;
    }
  }

  if (options.debug) 
    log_dbg("Uamallowed IP address #%d:%d: proto=%d host=%s port=%d", cnt, ptlen,
	    pt->proto, inet_ntoa(pt->host), pt->port);

  memcpy(&ptlist[cnt], pt, sizeof(pass_through));
  *ptcnt = cnt + 1;
  return 0;
}

int pass_throughs_from_string(pass_through *ptlist, size_t ptlen, size_t *ptcnt, char *s) {
  struct hostent *host;
  pass_through pt;
  char *t, *p1 = NULL, *p2 = NULL;
  char *p3 = malloc(strlen(s)+1);
  strcpy(p3, s);
  p1 = p3;
  
  if (options.debug) 
    log_dbg("Uamallowed %s", s);
  
  for ( ; p1; p1 = p2) {
    
    /* save the next entry position */
    if ((p2 = strchr(p1, ','))) { *p2=0; p2++; }
    
    /* clear the pass-through entry in case we partitially filled it already */
    memset(&pt, 0, sizeof(pass_through));
    
    /* eat whitespace */
    while (isspace(*p1)) p1++;
    
    /* look for specific protocols */
    if ((t = strchr(p1, ':'))) { 
      int pnum = 0;

      *t = 0;

#ifdef HAVE_GETPROTOENT      
      if (1) {
	struct protoent *proto = getprotobyname(p1);

	if (!proto && !strchr(p1, '.')) 
	  proto = getprotobynumber(atoi(p1));

	if (proto) 
	  pnum = proto->p_proto;
      }
#else
      if      (!strcmp(p1,"tcp"))  { pnum = DHCP_IP_TCP;  }
      else if (!strcmp(p1,"udp"))  { pnum = DHCP_IP_UDP;  }
      else if (!strcmp(p1,"icmp")) { pnum = DHCP_IP_ICMP; }
#endif

      if (pnum > 0) {
	/* if a protocol, skip ahead */
	pt.proto = pnum;
	p1 = t + 1;
      } else {
	/* if not a protocol, put the ':' back */
	*t = ':';
      }
    }
    
    /* look for an optional port */
    if ((t = strchr(p1, ':'))) { 
      pt.port = atoi(t+1); 
      *t = 0; 
    }
    
    if (strchr(p1, '/')) {	/* parse a network address */
      if (option_aton(&pt.host, &pt.mask, p1, 0)) {
	log_err(0, "Invalid uamallowed network address or mask %s!", s);
	continue;
      } 
      if (pass_through_add(ptlist, ptlen, ptcnt, &pt))
	log_err(0, "Too many pass-throughs! skipped %s", s);
    }
    else {	/* otherwise, parse a host ip or hostname */
      int j = 0;
      pt.mask.s_addr = 0xffffffff;

      if (!(host = gethostbyname(p1))) {
	log_err(errno, "Invalid uamallowed domain or address: %s!", p1);
	continue;
      }

      while (host->h_addr_list[j] != NULL) {
	pt.host = *((struct in_addr *) host->h_addr_list[j++]);
	if (pass_through_add(ptlist, ptlen, ptcnt, &pt))
	  log_err(0, "Too many pass-throughs! skipped %s", s);
      }
    }
  }

  free(p3);
  return 0;
}

