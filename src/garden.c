/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007-2011 Coova Technologies, LLC. <support@coova.com>
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
#include "debug.h"

#ifdef ENABLE_CHILLIQUERY
void garden_print_list(int fd, pass_through *ptlist, int ptcnt) {
  char mask[32];
  char line[512];
  pass_through *pt;
  int i;

  for (i = 0; i < ptcnt; i++) {
    pt = &ptlist[i];
    
    safe_strncpy(mask, inet_ntoa(pt->mask), sizeof(mask));
    
    safe_snprintf(line, sizeof(line),
		  "host=%-16s mask=%-16s proto=%-3d port=%-3d\n", 
		  inet_ntoa(pt->host), mask,
		  pt->proto, pt->port);
    
    if (!write(fd, line, strlen(line))) /* error */;
  }
}

void garden_print(int fd) {
  char *line = "main garden:\n";
  if (!write(fd, line, strlen(line))) /* error */;
  garden_print_list(fd, 
		    _options.pass_throughs, 
		    _options.num_pass_throughs);
  line = "dhcp(dns) garden:\n";
  if (!write(fd, line, strlen(line))) /* error */;
  garden_print_list(fd, 
		    dhcp->pass_throughs, 
		    dhcp->num_pass_throughs);
}
#endif

int garden_check(pass_through *ptlist, int ptcnt, uint8_t *pack, int dst) {
  struct pkt_iphdr_t *iph = iphdr(pack);
  struct pkt_tcphdr_t *tcph = tcphdr(pack);
  struct pkt_udphdr_t *udph = udphdr(pack);
  pass_through *pt;
  int i;

  for (i = 0; i < ptcnt; i++) {
    pt = &ptlist[i];
    if (pt->proto == 0 || iph->protocol == pt->proto)
      if (pt->host.s_addr == 0 || 
	  pt->host.s_addr == ((dst ? iph->daddr : iph->saddr) & pt->mask.s_addr))
	if (pt->port == 0 || 
	    (iph->protocol == PKT_IP_PROTO_TCP && (dst ? tcph->dst : tcph->src) == htons(pt->port)) ||
	    (iph->protocol == PKT_IP_PROTO_UDP && (dst ? udph->dst : udph->src) == htons(pt->port)))
	  return 1;
  }

  return 0;
}

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
    while (isspace((int) *p1)) p1++;
    
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

  pt.inuse = 1;
  memcpy(&ptlist[cnt], &pt, sizeof(pt));
  *ptcnt = cnt + 1;
  return 0;
}
#endif

#ifdef ENABLE_UAMDOMAINFILE

typedef struct uamdomain_regex_t {
  regex_t re;
  char neg;
  struct uamdomain_regex_t *next;
} uamdomain_regex;

static uamdomain_regex * _list_head = 0;

void garden_free_domainfile() {
  while (_list_head) {
    uamdomain_regex * n = _list_head;
    _list_head = _list_head->next;
    regfree(&n->re);
    free(n);
  }
}

void garden_load_domainfile() {
  garden_free_domainfile();
  if (!_options.uamdomainfile) return;
  else {
    char * line = 0;
    size_t len = 0;
    ssize_t read;
    FILE* fp;

    uamdomain_regex * uam_end = 0;

    fp = fopen(_options.uamdomainfile, "r");
    if (!fp) { 
      log_err(errno, "could not open file %s", _options.uamdomainfile); 
      return; 
    }
    
    while ((read = getline(&line, &len, fp)) != -1) {
      if (read <= 0) continue;
      else if (!line[0] || line[0] == '#' || isspace((int) line[0])) continue;
      else {
	
	uamdomain_regex * uam_re = (uamdomain_regex *)
	  calloc(sizeof(uamdomain_regex), 1);

	char * pline = line;
	
	while (isspace((int) pline[read-1]))
	  pline[--read] = 0;

	if (pline[0] == '!') {
	  uam_re->neg = 1;
	  pline++;
	}
	
	log_dbg("compiling %s", pline);
	if (regcomp(&uam_re->re, pline, REG_EXTENDED | REG_NOSUB)) {
	  log_err(0, "could not compile regex %s", line);
	  free(uam_re);
	  continue;
	}
	
	if (uam_end) {
	  uam_end->next = uam_re;
	  uam_end = uam_re;
	} else {
	  _list_head = uam_end = uam_re;
	}
      }
    }	
    
    fclose(fp);
    
    if (line)
      free(line);
  }
}

int garden_check_domainfile(char *question) {
  uamdomain_regex * uam_re = _list_head;
  
  while (uam_re) {
    int match = !regexec(&uam_re->re, question, 0, 0, 0);
    
#if(_debug_)
    if (match)
      log_dbg("matched DNS name %s", question);
#endif

    if (match) return uam_re->neg ? 0 : 1;
    
    uam_re = uam_re->next;
  }

  return 0;
}

#endif
