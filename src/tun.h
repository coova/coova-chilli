/* 
 * TUN interface functions.
 * Copyright (C) 2002, 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007-2008 David Bird <david@coova.com>
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
#include "net.h"

#define PACKET_MAX      8196 /* Maximum packet size we receive */
#define TUN_SCRIPTSIZE   512
#define TUN_ADDRSIZE     128
#define TUN_NLBUFSIZE   1024
#define TUN_MAX_INTERFACES 16

/* ***********************************************************
 * Information storage for each tun instance
 *************************************************************/

struct tun_t {
  int debug;
  int addrs;   /* Number of allocated IP addresses */
  int routes;  /* One if we allocated an automatic route */
  int routeidx; /* default route interface index */
  int (*cb_ind) (struct tun_t *tun, void *pack, size_t len, int idx);

  int _interface_count;
  struct _net_interface _interfaces[TUN_MAX_INTERFACES];

  void *table;
};

#define tun(x,i) ((x)->_interfaces[(i)])
#define tuntap(x) tun((x),0)

int tun_new(struct tun_t **tun);
int tun_free(struct tun_t *this);
int tun_decaps(struct tun_t *this, int idx);
int tun_encaps(struct tun_t *this, void *pack, size_t len, int idx);

/*int tun_addaddr(struct tun_t *this, struct in_addr *addr, struct in_addr *dstaddr, struct in_addr *netmask);
int tun_setaddr(struct tun_t *this, struct in_addr *our_adr, struct in_addr *his_adr, struct in_addr *net_mask);
int tun_addroute(struct tun_t *this, struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask);
int tun_delroute(struct tun_t *this, struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask);*/

int tun_set_cb_ind(struct tun_t *this, int (*cb_ind) (struct tun_t *tun, void *pack, size_t len, int idx));

int tun_setaddr(struct tun_t *this, struct in_addr *addr, struct in_addr *dstaddr, struct in_addr *netmask);

int tun_runscript(struct tun_t *tun, char* script);

net_interface *tun_nextif(struct tun_t *tun);
int tun_name2idx(struct tun_t *tun, char *name);

#define tun_maxfd(tun,max) {int i; for (i=0; i<(tun)->_interface_count; i++) net_maxfd(&(tun)->_interfaces[i], (max));}
#define tun_fdset(tun,fds) {int i; for (i=0; i<(tun)->_interface_count; i++) net_fdset(&(tun)->_interfaces[i], (fds));}
#define tun_ckset(tun,fds) {int i; for (i=0; i<(tun)->_interface_count; i++) { \
  if (net_isset(&(tun)->_interfaces[i], (fds)) && tun_decaps((tun), i) < 0) log_err(0, "tun_decaps()"); } }
#define tun_close(tun) {int i; for (i=0; i<(tun)->_interface_count; i++) net_close(&(tun)->_interfaces[i]);}

#endif	/* !_TUN_H */
