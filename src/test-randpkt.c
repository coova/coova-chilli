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

#define MAIN_FILE

#include "chilli.h"

struct options_t _options;

int test_dhcp(int cnt) {
  uint8_t bcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  struct _net_interface i; 
  int c = 0;

  memset(&i, 0, sizeof(i));

  if (!_options.dhcpif) {
    printf("give this util the --dhcpif argument to specify the interface\n");
    exit(1);
  }

  if (net_init(&i, _options.dhcpif, ETH_P_ALL, 1, 0) < 0) {
    perror("problem");
    exit(0);
  }

  /* we want the same, but random, MAC address, 
     to not overload our database */
  srand(time(0));

  while (c++ < cnt)
  {
    uint8_t packet[PKT_BUFFER];
    uint8_t chaddr[] = { rand(), rand(), rand(), rand(), rand(), rand() };
    int x = sizeof(packet);
    int len = rand() % (x - 1);
    len++;

    while (x-- > 0) 
      packet[x] = rand();

    if (0) { /* vlan */
      *(uint16_t *)&packet[12] = htons(PKT_ETH_PROTO_8021Q); /* tpid */
      *(uint16_t *)&packet[16] = htons(PKT_ETH_PROTO_IP); /* Ether Proto */
      *(uint8_t  *)&packet[18] = PKT_IP_VER_HLEN; /* ip version hlen */
      *(uint16_t *)&packet[20] = htons((rand() % 1000) + 20); /* IP tot_len */
      *(uint8_t  *)&packet[27] = PKT_IP_PROTO_TCP;
      memcpy(packet, bcast, 6);
    }
    else if (1) { /* dns */
      uint16_t len = (rand() % 1000);
      *(uint16_t *)&packet[12] = htons(PKT_ETH_PROTO_IP); /* Ether Proto */
      *(uint8_t  *)&packet[14] = PKT_IP_VER_HLEN; /* ip version hlen */
      *(uint16_t *)&packet[16] = htons(len + 20); /* IP tot_len; ip + 2 */
      *(uint16_t *)&packet[20] = 0; /* frag_off */
      *(uint8_t  *)&packet[23] = PKT_IP_PROTO_UDP; /* ip + 9; end + 20 */
      *(uint8_t  *)&packet[26] = 192; /* ip + 12; */
      *(uint8_t  *)&packet[27] = 168; /* ip + 12; */
      *(uint8_t  *)&packet[28] = 10; /* ip + 12; */
      *(uint8_t  *)&packet[29] = 1; /* ip + 12; */
      *(uint8_t  *)&packet[30] = 10; /* ip + 16; */
      *(uint8_t  *)&packet[31] = 1; 
      *(uint8_t  *)&packet[32] = 0; 
      *(uint8_t  *)&packet[33] = 2; 
      *(uint16_t *)&packet[34] = htons(53); 
      *(uint16_t *)&packet[36] = htons(53); 
      *(uint16_t *)&packet[38] = htons(len); 
      chksum((struct pkt_iphdr_t *)&packet[14]);
      memcpy(packet, bcast, 6);
    }
    else if (0) { /* radius */
      uint16_t len = (rand() % 1000);
      *(uint16_t *)&packet[12] = htons(PKT_ETH_PROTO_IP); /* Ether Proto */
      *(uint8_t  *)&packet[14] = PKT_IP_VER_HLEN; /* ip version hlen */
      *(uint16_t *)&packet[16] = htons(len + 20); /* IP tot_len; ip + 2 */
      *(uint8_t  *)&packet[23] = PKT_IP_PROTO_UDP; /* ip + 9; */
      *(uint8_t  *)&packet[26] = 127; /* ip + 12; */
      *(uint8_t  *)&packet[27] = 0; /* ip + 12; */
      *(uint8_t  *)&packet[28] = 0; /* ip + 12; */
      *(uint8_t  *)&packet[29] = 1; /* ip + 12; */
      *(uint8_t  *)&packet[30] = 10; /* ip + 16; */
      *(uint8_t  *)&packet[31] = 1; 
      *(uint8_t  *)&packet[32] = 0; 
      *(uint8_t  *)&packet[33] = 1; 
      *(uint16_t *)&packet[36] = htons(1812); 
      *(uint16_t *)&packet[38] = htons(len); 
      memcpy(packet, bcast, 6);
    }
    else if (0) { /* ip */
      *(uint16_t *)&packet[12] = htons(PKT_ETH_PROTO_IP); /* Ether Proto */
      *(uint8_t  *)&packet[14] = PKT_IP_VER_HLEN; /* ip version hlen */
      *(uint16_t *)&packet[16] = htons((rand() % 1000) + 20); /* IP tot_len */
      *(uint8_t  *)&packet[23] = PKT_IP_PROTO_TCP;
      memcpy(packet, bcast, 6);
    }
    else if (0) { /* arp */
      *(uint16_t *)&packet[12] = htons(PKT_ETH_PROTO_ARP);
      *(uint16_t *)&packet[20] = htons(DHCP_ARP_REQUEST);
      memcpy(packet, bcast, 6);
      memcpy(packet + 6, bcast, 6);
    }

    dhcp_send(0, &i, chaddr, packet, len);
  }

  return 0;
}

int main(int argc, char **argv) {
  int cnt = 1;

  if (argc > 1) 
    cnt = atoi(argv[1]);

  options_init();

  _options.dhcpif = "eth0";

  return test_dhcp(cnt);
}
