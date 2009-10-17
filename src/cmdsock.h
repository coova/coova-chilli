/* 
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
#ifndef CMDSOCK
#define CMDSOCK

#define  CMDSOCK_DHCP_LIST      0
#define  CMDSOCK_DHCP_RELEASE   1
#define  CMDSOCK_LIST           2
#define  CMDSOCK_SHOW           3
#define  CMDSOCK_AUTHORIZE      4
#define  CMDSOCK_DHCP_DROP      5
#define  CMDSOCK_ROUTE          6
#define  CMDSOCK_ROUTE_SET      7
#define  CMDSOCK_ENTRY_FOR_IP   8
#define  CMDSOCK_ENTRY_FOR_MAC  9
#define  CMDSOCK_RELOAD        10
#ifdef ENABLE_STATFILE
#define  CMDSOCK_STATUSFILE    11
#endif
#define  CMDSOCK_OPT_JSON      (1)

#include "pkt.h"
#include "session.h"

struct cmdsock_request { 
  uint16_t type;
  uint16_t options;
  union {
    unsigned char mac[PKT_ETH_ALEN];
    struct cmdsock_session {
      struct in_addr ip;
      char username[256];
      char sessionid[17];
      struct session_params params;
    } sess;
  } data;
}  __attribute__((packed));

typedef struct cmdsock_request CMDSOCK_REQUEST;

#endif /* CMDSOCK */
