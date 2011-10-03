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
#ifndef CMDSOCK
#define CMDSOCK

#define  CMDSOCK_DHCP_LIST      0
#define  CMDSOCK_DHCP_RELEASE   1
#define  CMDSOCK_LIST           2
#define  CMDSOCK_SHOW           3
#define  CMDSOCK_AUTHORIZE      4
#define  CMDSOCK_DHCP_DROP      5
#define  CMDSOCK_ENTRY_FOR_IP   6
#define  CMDSOCK_ENTRY_FOR_MAC  7
#define  CMDSOCK_RELOAD         8
#define  CMDSOCK_PROCS          9
#define  CMDSOCK_UPDATE        10
#define  CMDSOCK_LOGIN         11
#define  CMDSOCK_LOGOUT        12
#define  CMDSOCK_LIST_IPPOOL   13
#define  CMDSOCK_LIST_RADQUEUE 14
#define  CMDSOCK_LIST_GARDEN   15
#ifdef ENABLE_STATFILE
#define  CMDSOCK_STATUSFILE    16
#endif
#ifdef ENABLE_CLUSTER
#define  CMDSOCK_PEERS         17
#define  CMDSOCK_PEER_SET      18
#endif
#ifdef ENABLE_MULTIROUTE
#define  CMDSOCK_ROUTE         19
#define  CMDSOCK_ROUTE_SET     20
#define  CMDSOCK_ROUTE_GW      21
#endif
#define  CMDSOCK_OPT_JSON      (1)

#include "pkt.h"
#include "session.h"

struct cmdsock_request { 
  uint16_t type;
  uint16_t options;
  unsigned char mac[PKT_ETH_ALEN];
  struct in_addr ip;
  union {
    struct cmdsock_session {
      char username[256];
      char password[256];
      char sessionid[17];
      struct session_params params;
    } sess;
    char data[1024];
  } d;
}  __attribute__((packed));

typedef struct cmdsock_request CMDSOCK_REQUEST;

#endif /* CMDSOCK */
