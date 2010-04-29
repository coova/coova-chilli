/* 
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

#define cksum_wrap(c) (c=(c>>16)+(c&0xffff),(~(c+(c>>16))&0xffff))

uint32_t
in_cksum(uint16_t *addr, int len) {
  int         nleft = len;
  uint32_t    sum = 0;
  uint16_t  * w = addr;
  
  while (nleft > 1) {
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
  uint16_t hlen;
  uint32_t sum;
  uint16_t len;

  /* Only IPv4 currently */
  if (iph->version_ihl != PKT_IP_VER_HLEN)
    return -1;

  /* Header length */
  hlen = iph->version_ihl & 0x0f;
  hlen <<= 2;

  len = ntohs(iph->tot_len);

  /* XXX: redundant */
  if (hlen != PKT_IP_HLEN)
    return -1;

  if (len > PKT_BUFFER) 
    return -1; /* too long? */
  if (len < hlen) 
    return -1; /* too short? */

  switch(iph->protocol) {
  case PKT_IP_PROTO_TCP:
    {
      struct pkt_tcphdr_t *tcph = (struct pkt_tcphdr_t *)(((void *)iph) + hlen);
      
      len -= hlen; /* length of tcp header + data */
      
      tcph->check = 0;
      sum  = in_cksum(((uint16_t *)iph)+6/*saddr*/, 8);
      sum += ntohs(IPPROTO_TCP + len);
      sum += in_cksum((uint16_t *)tcph, len);
      tcph->check = cksum_wrap(sum);
    }
    break;
    
  case PKT_IP_PROTO_UDP:
    {
      struct pkt_udphdr_t *udph = (struct pkt_udphdr_t *)(((void *)iph) + hlen);
      uint16_t udplen = ntohs(udph->len);

      if (udplen > len)
	return -1;
      
      udph->check = 0;
      sum  = in_cksum(((uint16_t *)iph)+6/*saddr*/, 8);
      sum += ntohs(IPPROTO_UDP + udplen);
      sum += in_cksum((uint16_t *)udph, udplen);
      udph->check = cksum_wrap(sum);
    }
    break;

    /* not affected by NAT'ing, so..
  case PKT_IP_PROTO_ICMP:
    {
      struct pkt_icmphdr_t *icmph = (struct pkt_icmphdr_t *)(((void *)iph) + hlen);
      len -= hlen; 
      icmph->check = 0;
      sum = in_cksum((uint16_t *)icmph, len);
      icmph->check = cksum_wrap(sum);
    }
    break;
    */
  }
  
  iph->check = 0;
  sum = in_cksum((uint16_t *)iph, hlen);
  iph->check = cksum_wrap(sum);
  
  return 0;
}

