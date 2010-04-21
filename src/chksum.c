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
      sum  = in_cksum(((uint16_t *)iph)+6/*saddr*/, 8);
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
      sum  = in_cksum(((uint16_t *)iph)+6/*saddr*/, 8);
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

