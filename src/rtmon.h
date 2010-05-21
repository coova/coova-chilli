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


#ifndef _RTMON_H
#define _RTMON_H

#include "system.h"
#include "pkt.h"

struct rtmon_iface {
  int index;
  uint16_t protocol;
  uint8_t hwaddr[PKT_ETH_ALEN];
  char devname[IFNAMSIZ+1];
  int devflags;
  int mtu;

  struct in_addr address;
  struct in_addr network;
  struct in_addr netmask;
  struct in_addr broadcast;
  struct in_addr gateway;

  char has_data;
};

struct rtmon_route {
  int if_index;
  struct in_addr destination;
  struct in_addr netmask;
  struct in_addr gateway;
  uint8_t gwaddr[PKT_ETH_ALEN];
  char has_data;
};

#define MAX_IFACES 16
#define MAX_ROUTES 16

struct rtmon_t {
  int fd;
  struct rtmon_iface _ifaces[MAX_IFACES];
  struct rtmon_route _routes[MAX_ROUTES];
};

typedef int (*rtmon_callback)(struct rtmon_t *rtmon, 
			      struct rtmon_iface *iface,
			      struct rtmon_route *route);

int rtmon_open_netlink();
int rtmon_read_event(struct rtmon_t *rtmon, rtmon_callback func);

#endif
