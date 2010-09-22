/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007-2010 Coova Technologies, LLC. <support@coova.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include "chilli.h"

int pass_through_add(pass_through *ptlist, uint32_t ptlen,
		     uint32_t *ptcnt, pass_through *pt) {
  uint32_t cnt = *ptcnt;
  int i;

  if (cnt >= ptlen) {
    if (_options.debug) 
      log_dbg("No more room for walled garden entries");
    return -1;
  }

  for (i=0; i < cnt; i++) {
    if (!memcmp(&ptlist[i],pt,sizeof(pass_through))) {
      if (_options.debug) 
	log_info("Uamallowed already exists #%d:%d: proto=%d host=%s port=%d", i, ptlen,
		 pt->proto, inet_ntoa(pt->host), pt->port);
      return 0;
    }
  }

  if (_options.debug) 
    log_info("Uamallowed IP address #%d:%d: proto=%d host=%s port=%d", cnt, ptlen,
	     pt->proto, inet_ntoa(pt->host), pt->port);

  memcpy(&ptlist[cnt], pt, sizeof(pass_through));
  *ptcnt = cnt + 1;
  return 0;
}

int pass_throughs_from_string(pass_through *ptlist, uint32_t ptlen, 
			      uint32_t *ptcnt, char *s) {
  struct hostent *host;
  pass_through pt;
  char *t, *p1 = NULL, *p2 = NULL;
  char *p3 = malloc(strlen(s)+1);

  strcpy(p3, s);
  p1 = p3;
  
  if (_options.debug) 
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

#ifdef ENABLE_CHILLIREDIR
int regex_pass_throughs_from_string(regex_pass_through *ptlist, uint32_t ptlen, 
				    uint32_t *ptcnt, char *s) {
  uint32_t cnt = *ptcnt;
  regex_pass_through pt;
  char *p, *st;
  int stage = 0;

  memset(&pt, 0, sizeof(pt));

  for (st = s; (p = strtok(st, "::")); st = 0, stage++) {
    int is_wild = !strcmp(p,"*");
    if (!is_wild) {
      int is_negate = (*p == '!');
      if (is_negate) p++;
      switch (stage) {
      case 0: safe_strncpy(pt.regex_host, p, sizeof(pt.regex_host)); pt.neg_host = is_negate; break;
      case 1: safe_strncpy(pt.regex_path, p, sizeof(pt.regex_path)); pt.neg_path = is_negate; break;
      case 2: safe_strncpy(pt.regex_qs,   p, sizeof(pt.regex_qs));   pt.neg_qs   = is_negate; break;
      }
    }
  }

  memcpy(&ptlist[cnt], &pt, sizeof(pt));
  *ptcnt = cnt + 1;
  return 0;
}
#endif
