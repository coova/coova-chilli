/* 
 * CoovaChilli: A Wireless LAN Access Point Controller.
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
#include "dns.h"
#include "tun.h"
#include "session.h"
#include "chilli.h"
#include "options.h"

int pkt_shape(uint8_t *packet, size_t *length) {

  int optval = options()->tcpwin;

  if (optval) {
    struct pkt_iphdr_t *iph = iphdr(packet);
    if (iph->protocol == PKT_IP_PROTO_TCP) {
      struct pkt_tcphdr_t *tcph = tcphdr(packet);
      if (ntohs(tcph->win) > optval) {
	tcph->win = htons(optval);
	chksum(iph);
      }
    }
  }

  optval = options()->tcpmss;
  if (optval) {
    struct pkt_iphdr_t *iph = iphdr(packet);
    if (iph->protocol == PKT_IP_PROTO_TCP) {

      struct pkt_tcphdr_t *tcph = tcphdr(packet);
      int off = tcph->offres >> 4;
      int hasmss = 0;

#if(0)
      log_dbg("-->> offset: %d", off);
#endif

      if (off > 5) {
	uint8_t *opts = tcph->options;
	uint8_t type;
	uint8_t len;
	int words = off - 5;
	int done = 0;
	int i = 0;

	while (!done && (i / 4) < words) {
	  switch(type = opts[i++]) {
	  case 0: 
	    done = 1; 
	    break;

	  case 1: 
#if(0)
	    log_dbg("TCP OPTIONS: NOP");
#endif
	    break;

	  case 2: 
#if(0)
	    log_dbg("TCP OPTIONS: MSS");
#endif
	    len = opts[i++];
	    if (ntohs(*((uint16_t *)&opts[i])) > optval) {
	      *((uint16_t *)&opts[i]) = htons(optval);
	      chksum(iph);
	    }
	    hasmss = 1;
	    i += 2;
	    break;

	  default:
	    len = opts[i++];
#if(0)
	    log_dbg("TCP OPTIONS: type %d len %d", type, len); 
#endif
	    i += len - 2;
	    break;
	  }
	}
      }

      if (!hasmss && *length < 1400 && tcphdr_syn(tcph)) {
	uint8_t p[PKT_BUFFER];
	memcpy(p, packet, *length);
	{
	  struct pkt_iphdr_t *p_iph = iphdr(p);
	  struct pkt_tcphdr_t *p_tcph = tcphdr(p);

	  uint8_t *fopt = p_tcph->options + ((off - 5) * 4);
	  uint8_t *copt = tcph->options + ((off - 5) * 4);

	  int dlen = *length - sizeofip(packet) - (off * 4);

	  /*log_dbg("TCP DATA: (%d - %d - %d) len %d", *length, sizeofip(packet), (off * 4), dlen); */

	  p_tcph->offres = (off + 1) << 4;

	  fopt[0] = 2;
	  fopt[1] = 4;

	  *((uint16_t *)&fopt[2]) = htons(optval);

	  if (dlen > 0) {
	    memcpy(fopt + 4, copt, dlen);
	  }

	  *length = *length + 4;
	  p_iph->tot_len = htons(ntohs(p_iph->tot_len)+4);

	  chksum(p_iph);

	  memcpy(packet, p, *length);
	}
      }
    }
  }

  return 0;
}

