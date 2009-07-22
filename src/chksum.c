/*
 * Chksum library functions
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#include "system.h"
#include "pkt.h"
#include "options.h"
#include "syserr.h"

#define cksum_wrap(c) (c=(c>>16)+(c&0xffff),(~(c+(c>>16))&0xffff))

int
in_cksum(uint16_t *addr, size_t len)
{
  size_t      nleft = len;
  uint32_t    sum = 0;
  uint16_t  * w = addr;
  
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }
  
  if (nleft == 1) {
    uint16_t ans = 0;
    *(unsigned char *)(&ans) = *(unsigned char *)w ;
    sum += ans;
  }
  
  return(sum);
}

int chksum(struct pkt_iphdr_t *iph) {
  size_t hlen = (iph->version_ihl & 0x0f) << 2;
  int sum;

  switch(iph->protocol) {
  case PKT_IP_PROTO_TCP:
    {
      struct pkt_tcphdr_t *tcph = (struct pkt_tcphdr_t *)(((void *)iph) + hlen);
      size_t len = (size_t)ntohs(iph->tot_len);
      
      if (len > 2000) return -1; /* too long? */
      
      len -= (iph->version_ihl & 0x0f) << 2;
      
      if (len < 20) return -1;  /* too short? */
      
      tcph->check = 0;
      sum = in_cksum(((uint16_t *)iph)+6/*saddr*/, 8);
      sum += ntohs(IPPROTO_TCP + len);
      sum += in_cksum((uint16_t *)tcph, len);
      tcph->check = cksum_wrap(sum);
    }
    break;
    
  case PKT_IP_PROTO_UDP:
    {
      struct pkt_udphdr_t *udph = (struct pkt_udphdr_t *)(((void *)iph) + hlen);
      size_t len = (size_t)ntohs(udph->len);
      
      udph->check = 0;
      sum = in_cksum(((uint16_t *)iph)+6/*saddr*/, 8);
      sum += ntohs(IPPROTO_UDP + len);
      sum += in_cksum((uint16_t *)udph, len);
      udph->check = cksum_wrap(sum);
    }
    break;
  }
  
  iph->check = 0;
  sum = in_cksum((uint16_t *)iph, hlen);
  iph->check = cksum_wrap(sum);
  
  return 0;
}

