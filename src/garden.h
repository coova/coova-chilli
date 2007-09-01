/* 
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#ifndef _GARDEN_H
#define _GARDEN_H

typedef struct pass_through_t {
  struct in_addr host;              /* IP or Network */
  struct in_addr mask;              /* Netmask */
  uint8_t proto;                       /* TCP, UDP, or ICMP */
  uint16_t port;                       /* TCP or UDP Port */
} pass_through;

int pass_through_add(pass_through *ptlist, size_t ptlen, size_t *ptcnt, pass_through *pt);
int pass_throughs_from_string(pass_through *ptlist, size_t ptlen, size_t *ptcnt, char *s);

#endif
