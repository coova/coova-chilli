/* 
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

#define _debug_ 0
#include "chilli.h"
#include "debug.h"

#define antidnstunnel _options.dnsparanoia

extern struct dhcp_t *dhcp;

int
dns_fullname(char *data, size_t dlen,      /* buffer to store name */
	     uint8_t *res, size_t reslen,  /* current resource */
	     uint8_t *opkt, size_t olen,   /* original packet */
	     int lvl) {
  int ret = 0;
  char *d = data;
  unsigned char l;

  if (lvl >= 15) return -1;

#if(_debug_)
  log_dbg("dlen=%d reslen=%d olen=%d lvl=%d", 
	  dlen, reslen, olen, lvl);
#endif
  
  while (reslen-- > 0 && ++ret && (l = *res++) != 0) {

    if ((l & 0xC0) == 0xC0) {
      if (reslen == 0) return -1;
      else {
	unsigned short offset = ((l & ~0xC0) << 8) + *res;

	ret++;
	
	if (offset > olen) {
	  log_dbg("bad value");
	  return -1;
	}
	
#if(_debug_)
	log_dbg("skip[%d] dlen=%d", offset, dlen);
#endif
	
	if (dns_fullname(d, dlen, 
			 opkt + (size_t) offset, 
			 olen - (size_t) offset, 
			 opkt, olen, lvl+1) < 0)
	  return -1;
	break;
      } 
    }
    
    if (l >= dlen || l >= reslen) {
      log_dbg("bad value %d/%d/%d", l, dlen, reslen);
      return -1;
    }
    
#if(_debug_)
    log_dbg("part[%.*s] reslen=%d l=%d dlen=%d",
	    l, res, reslen, l, dlen);
#endif
    
    memcpy(d, res, l);
    d += l; 
    dlen -= l;
    res += l;
    reslen -= l;
    ret += l;

    *d = '.';
    d += 1; 
    dlen -= 1;
  }
  
  if (lvl == 0) {
    int len = strlen((char *)data);
    if (len && len == (d - data) && data[len-1] == '.')
      data[len-1]=0;
  }

  return ret;
}

static void 
add_A_to_garden(uint8_t *p) {
  struct in_addr reqaddr;
  pass_through pt;
  memcpy(&reqaddr.s_addr, p, 4);
  memset(&pt, 0, sizeof(pass_through));
  pt.mask.s_addr = 0xffffffff;
  pt.host = reqaddr;
  if (pass_through_add(dhcp->pass_throughs,
		       MAX_PASS_THROUGHS,
		       &dhcp->num_pass_throughs,
		       &pt))
    ;
}

int 
dns_copy_res(struct dhcp_conn_t *conn, int q, 
	     uint8_t **pktp, size_t *left, 
	     uint8_t *opkt,  size_t olen, 
	     uint8_t *question, size_t qsize,
	     int *qmatch, int mode) {

#define return_error { log_dbg("failed parsing DNS packet"); return -1; }

  uint8_t *p_pkt = *pktp;
  size_t len = *left;
  
  uint8_t name[PKT_IP_PLEN];
  size_t namelen = 0;
  
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdlen;

  uint32_t ul;
  uint16_t us;

#if(_debug_)
  log_dbg("%s: left=%d olen=%d qsize=%d",
	  __FUNCTION__, *left, olen, qsize);
#endif

  memset(name, 0, sizeof(name));
  namelen = dns_fullname((char*)name, sizeof(name)-1, p_pkt, len, opkt, olen, 0);
  if (namelen < 0) return -1;

  p_pkt += namelen;
  len -= namelen;

  if (antidnstunnel && namelen > 128) {
    log_warn(0,"dropping dns for anti-dnstunnel (namelen: %d)", namelen);
    return -1;
  }

  if (len < 4) return_error;

  memcpy(&us, p_pkt, sizeof(us));
  type = ntohs(us);
  p_pkt += 2;
  len -= 2;
  
  memcpy(&us, p_pkt, sizeof(us));
  class = ntohs(us);
  p_pkt += 2;
  len -= 2;
  
#if(_debug_)
  log_dbg("It was a dns record type: %d class: %d", type, class);
#endif

  /* if dnsparanoia, checks here */

  if (antidnstunnel) {
    switch (type) {
    case 1:/* A */ 
#if(_debug_)
      log_dbg("A record");
#endif
      break;
    case 5:/* CNAME */ 
#if(_debug_)
      log_dbg("CNAME record");
#endif
      break;
    default:
#if(_debug_)
      if (_options.debug) switch(type) {
	case 6:  log_dbg("SOA record"); break;
	case 12: log_dbg("PTR record"); break;
	case 15: log_dbg("MX record");  break;
	case 16: log_dbg("TXT record"); break;
	default: log_dbg("Record type %d", type); break;
	}
#endif
      log_warn(0, "dropping dns for anti-dnstunnel (type %d: length %d)", type, namelen);
      return -1;
    }
  }
  
  if (q) {
    if (dns_fullname((char *)question, qsize, *pktp, *left, opkt, olen, 0) < 0)
      return_error;
    
    log_dbg("DNS: %s", question);
    
    *pktp = p_pkt;
    *left = len;
    
    return 0;
  } 

  if (len < 6) return_error;
  
  memcpy(&ul, p_pkt, sizeof(ul));
  ttl = ntohl(ul);
  p_pkt += 4;
  len -= 4;
  
  memcpy(&us, p_pkt, sizeof(us));
  rdlen = ntohs(us);
  p_pkt += 2;
  len -= 2;
  
#if(_debug_)
  log_dbg("-> w ttl: %d rdlength: %d/%d", ttl, rdlen, len);
#endif
  
  if (len < rdlen) return_error;
  
  /*
   *  dns records 
   */  
  
  switch (type) {
    
  case 1:/* A */

#ifdef ENABLE_BONJOUR
    if (mode == DNS_MDNS_MODE) {
      size_t offset;
      for (offset=0; offset < rdlen; offset += 4) {
	struct in_addr reqaddr;
	memcpy(&reqaddr.s_addr, p_pkt+offset, 4);
#if(_debug_)
	log_dbg("mDNS %s = %s", name, inet_ntoa(reqaddr));
#endif
      }
      break;
    }
#endif    

#if(_debug_)
    log_dbg("A record");
#endif
    if (*qmatch == -1 &&_options.uamdomains && _options.uamdomains[0]) {
      int id;
      for (id=0; _options.uamdomains[id] && id < MAX_UAM_DOMAINS; id++) {
	
	size_t qst_len = strlen((char *)question);
	size_t dom_len = strlen(_options.uamdomains[id]);
	
#if(_debug_)
	log_dbg("checking %s [%s]",
		_options.uamdomains[id], question);
#endif
	
	if ( qst_len && dom_len && 
	     (
	      /*
	       *  Match if question equals the uamdomain
	       */
	      ( qst_len == dom_len &&
		!strcmp(_options.uamdomains[id], (char *)question) ) ||
	      /*
	       *  Match if the question is longer than uamdomain,
	       *  and ends with the '.' followed by uamdomain
	       */
	      ( qst_len > dom_len && 
		(_options.uamdomains[id][0] == '.' ||
		 question[qst_len - dom_len - 1] == '.') &&
		!strcmp(_options.uamdomains[id], 
			(char *)question + qst_len - dom_len) )
	      ) ) {
#if(_debug_)
	  log_dbg("matched %s [%s]", _options.uamdomains[id], question);
#endif
	  *qmatch = 1;
	  break;
	}
      }
    }
#ifdef ENABLE_UAMDOMAINFILE
    if (*qmatch == -1 && _options.uamdomainfile) {
      *qmatch = garden_check_domainfile((char *) question);
    }
#endif
    if (*qmatch == 1) {
      size_t offset;
      for (offset=0; offset < rdlen; offset += 4) {
	add_A_to_garden(p_pkt+offset);
      }
    }
    break;
    
  case 5:/* CNAME */
    log_dbg("CNAME record %s", name);
    break;

  case 16:/* TXT */
    log_dbg("TXT record %d", rdlen);
    if (_options.debug) {
      char *txt = (char *)p_pkt;
      int txtlen = rdlen;
      while (txtlen-- > 0) {
	uint8_t l = *txt++;
	if (l == 0) break;
	log_dbg("Text: %.*s", (int) l, txt);
	txt += l;
	txtlen -= l;
      }
    }
    break;

  default:

    if (_options.debug) switch(type) {
      case 6:  log_dbg("SOA record"); break;
      case 12: log_dbg("PTR record"); break;
      case 15: log_dbg("MX record");  break;
      case 47: log_dbg("NSEC record"); break;
      default: log_dbg("Record type %d", type); break;
    }

    if (antidnstunnel) {
      log_warn(0, "dropping dns for anti-dnstunnel (type %d: length %d)", type, rdlen);
      return -1;
    }

    break;
  }
  
  p_pkt += rdlen;
  len -= rdlen;
  
  *pktp = p_pkt;
  *left = len;

  return 0;
}
