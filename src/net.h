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


#ifndef _NET_H
#define _NET_H

#include "system.h"
#include "pkt.h"

#ifdef USING_PCAP
#include <pcap.h>
#endif

#if defined(__linux__)

#ifdef USING_MMAP
# ifdef TPACKET_HDRLEN
#  define HAVE_PACKET_RING
#  ifdef PACKET_RX_RING
#   define HAVE_PACKET_RX_RING
#  endif
#  ifdef PACKET_TX_RING
#   define HAVE_PACKET_TX_RING
#  endif
#  ifdef TPACKET2_HDRLEN
#   define HAVE_TPACKET2
#  else
#   define TPACKET_V1 0
#  endif
# endif
#endif

#endif

typedef struct _net_interface {
  uint8_t idx;

  /* hardware/link */
  uint16_t protocol;
  uint8_t hwtype;
  uint8_t hwaddr[PKT_ETH_ALEN];
  char devname[IFNAMSIZ+1];
  int devflags;
  int ifindex;
  int mtu;

  /* network/address */
  struct in_addr address;
  struct in_addr gateway;
  struct in_addr netmask;
  struct in_addr broadcast;

  /* socket/descriptor */
  int fd;

#ifdef USING_PCAP
  pcap_t *pd;
#endif

#ifdef USING_MMAP
  int cc;
  int offset;
  int snapshot;
  int buffer_size;
  int bufsize;
  int tp_version;
  int tp_hdrlen;
  size_t mmapbuflen;
  char *mmapbuf;
  char *buffer;
#endif

#if defined(__linux__)
  struct sockaddr_ll dest;
#endif

  /* routing */
  uint8_t gwaddr[PKT_ETH_ALEN];

  uint8_t flags;
#define NET_PROMISC (1<<0)
#define NET_USEMAC  (1<<1)
#define NET_ETHHDR  (1<<2)
} net_interface;

typedef int (*net_handler)(void *ctx, void *data, size_t len);

#define net_sflags(n,f) dev_set_flags((n)->devname, (f))
#define net_gflags(n) dev_get_flags((n)->devname, &(n)->devflags)

int net_open(net_interface *netif);
int net_open_eth(net_interface *netif);
int net_reopen(net_interface *netif);
int net_init(net_interface *netif, char *ifname, uint16_t protocol, int promisc, uint8_t *mac);
int net_route(struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask, int delete);
int net_set_mtu(net_interface *netif, size_t mtu);

ssize_t net_read(net_interface *netif, void *d, size_t slen);
ssize_t net_write(net_interface *netif, void *d, size_t slen);

ssize_t net_read_dispatch(net_interface *netif, net_handler func, void *ctx);

#define fd_zero(fds)        FD_ZERO((fds));
#define fd_set(fd,fds)      if ((fd) > 0) FD_SET((fd), (fds))
#define fd_isset(fd,fds)    ((fd) > 0) && FD_ISSET((fd), (fds))
#define fd_max(fd,max)      (max) = (max) > (fd) ? (max) : (fd)

#define net_maxfd(this,max) (max) = (max) > (this)->fd ? (max) : (this)->fd
#define net_fdset(this,fds) if ((this)->fd > 0) FD_SET((this)->fd, (fds))
#define net_isset(this,fds) ((this)->fd > 0) && FD_ISSET((this)->fd, (fds))
#if defined(USING_PCAP)
#define net_close(this)     if ((this)->pd) pcap_close((this)->pd); (this)->pd=0; (this)->fd=0
#else
#define net_close(this)     if ((this)->fd > 0) close((this)->fd); (this)->fd=0
#endif
#define net_add_route(dst,gw,mask) net_route(dst,gw,mask,0)
#define net_del_route(dst,gw,mask) net_route(dst,gw,mask,1)

int dev_set_flags(char const *dev, int flags);
int dev_get_flags(char const *dev, int *flags);
int dev_set_addr(char const *devname, struct in_addr *addr, 
		 struct in_addr *gateway, struct in_addr *netmask);

int net_set_address(net_interface *netif, struct in_addr *address, 
		    struct in_addr *gateway, struct in_addr *netmask);

#endif
