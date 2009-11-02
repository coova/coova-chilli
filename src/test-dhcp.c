/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
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

#define MAIN_FILE

#include "system.h"
#include "syserr.h"
#include "cmdline.h"
#include "dhcp.h"
#include "radius.h"
#include "radius_chillispot.h"
#include "radius_wispr.h"
#include "redir.h"
#include "chilli.h"
#include "options.h"

struct options_t _options;

int test_dhcp() {
  struct _net_interface i; 
  int cnt = 1000;
  int c = 0;

  memset(&i, 0, sizeof(i));

  if (!__options.dhcpif) {
    printf("give this util the --dhcpif argument to specify the interface\n");
    exit(1);
  }

  if (net_init(&i, __options.dhcpif, ETH_P_ALL, 1, 0) < 0) {
    perror("problem");
    exit(0);
  }

  /* we want the same, but random, MAC address, 
     to not overload our database */
  srand(1);

  while (c++<cnt)
  {
    uint8_t packet[PKT_BUFFER];
    
    struct pkt_ethhdr_t *packet_ethh;
    struct pkt_iphdr_t *packet_iph;
    struct pkt_udphdr_t *packet_udph;
    struct dhcp_packet_t *packet_dhcp;
    
    uint16_t length = 576 + 4; /* Maximum length */
    uint16_t udp_len = 576 - 20; /* Maximum length */
    size_t pos = 0;
    
    uint8_t chaddr[] = { rand(), rand(), rand(), rand(), rand(), rand() };
    uint8_t bcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    /* Get packet default values */
    memset(packet, 0, sizeof(packet));

    packet_ethh = ethhdr(packet);

    /* Ethernet header */
    memcpy(packet_ethh->dst, bcast, PKT_ETH_ALEN);
    memcpy(packet_ethh->src, chaddr, PKT_ETH_ALEN);
    packet_ethh->prot = htons(PKT_ETH_PROTO_IP);

    packet_iph = iphdr(packet);
    packet_udph = udphdr(packet);
    packet_dhcp = dhcppkt(packet);

    /* IP header */
    packet_iph->version_ihl = PKT_IP_VER_HLEN;
    packet_iph->tos = 0;
    packet_iph->tot_len = 0; /* Calculate at end of packet */
    packet_iph->id = 0;
    packet_iph->frag_off = 0;
    packet_iph->ttl = 0x10;
    packet_iph->protocol = 0x11;
    packet_iph->check = 0; /* Calculate at end of packet */

    packet_iph->daddr = ~0; 

    /* UDP packet */
    packet_udph->dst = htons(DHCP_BOOTPS);
    packet_udph->src = htons(DHCP_BOOTPC);

    /* DHCP packet */
    packet_dhcp->op     = DHCP_BOOTREQUEST;
    packet_dhcp->htype  = DHCP_HTYPE_ETH;
    packet_dhcp->hlen   = PKT_ETH_ALEN;
    packet_dhcp->xid      = rand();
    packet_dhcp->flags[0] = 0x80;
    packet_dhcp->flags[1] = 0;
    packet_dhcp->giaddr   = 0;

    memcpy(&packet_dhcp->chaddr, chaddr, DHCP_CHADDR_LEN);

    packet_dhcp->options[pos++] = 0x63;
    packet_dhcp->options[pos++] = 0x82;
    packet_dhcp->options[pos++] = 0x53;
    packet_dhcp->options[pos++] = 0x63;
    
    packet_dhcp->options[pos++] = DHCP_OPTION_MESSAGE_TYPE;
    packet_dhcp->options[pos++] = 1;
    packet_dhcp->options[pos++] = DHCPDISCOVER;

    packet_dhcp->options[pos++] = DHCP_OPTION_END;
    
    /* UDP header */
    udp_len = pos + DHCP_MIN_LEN + PKT_UDP_HLEN;
    packet_udph->len = htons(udp_len);
    
    /* IP header */
    packet_iph->tot_len = htons(udp_len + PKT_IP_HLEN);
    
    /* Work out checksums */
    chksum(packet_iph);
    
    /* Calculate total length */
    length = udp_len + sizeofip(packet);
    printf("sending %d bytes to fd %d\n",length,i.fd);

    if (dhcp_send(0, &i, bcast, packet, length)) {
      perror("error");
      exit(1);
    }
  }

  return 0;
}

int main(int argc, char **argv) {
  options_init();

  __options.dhcpif = "eth0";

  return test_dhcp();
}
