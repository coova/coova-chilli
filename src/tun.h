/* 
 * TUN interface functions.
 * Copyright (C) 2002, 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007 David Bird <david@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#ifndef _TUN_H
#define _TUN_H

#include "pkt.h"

#define PACKET_MAX      8196 /* Maximum packet size we receive */
#define TUN_SCRIPTSIZE   512
#define TUN_ADDRSIZE     128
#define TUN_NLBUFSIZE   1024

/* ***********************************************************
 * Information storage for each tun instance
 *************************************************************/

struct tun_t {
  int debug;
  int fd;                /* File descriptor to tun interface */
  struct in_addr addr;
  struct in_addr dstaddr;
  struct in_addr netmask;
  int addrs;             /* Number of allocated IP addresses */
  int routes;            /* One if we allocated an automatic route */
  char devname[IFNAMSIZ];/* Name of the tun device */
  unsigned char tap_hwaddr[PKT_ETH_ALEN]; /* Hardware address of tap interface */
  int (*cb_ind) (struct tun_t *tun, void *pack, size_t len);
};

extern int tun_new(struct tun_t **tun, int txqlen);
extern int tun_free(struct tun_t *tun);
extern int tun_decaps(struct tun_t *this);
extern int tun_encaps(struct tun_t *tun, void *pack, size_t len);

extern int tun_addaddr(struct tun_t *this, struct in_addr *addr,
		       struct in_addr *dstaddr, struct in_addr *netmask);

extern int tun_setaddr(struct tun_t *this, struct in_addr *our_adr, 
		       struct in_addr *his_adr, struct in_addr *net_mask);

int tun_addroute(struct tun_t *this, struct in_addr *dst, 
		 struct in_addr *gateway, struct in_addr *mask);

int tun_delroute(struct tun_t *this, struct in_addr *dst,
		 struct in_addr *gateway, struct in_addr *mask);

extern int tun_set_cb_ind(struct tun_t *this, 
     int (*cb_ind) (struct tun_t *tun, void *pack, size_t len));


extern int tun_runscript(struct tun_t *tun, char* script);

#endif	/* !_TUN_H */
