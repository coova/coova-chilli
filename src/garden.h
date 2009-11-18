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


#ifndef _GARDEN_H_
#define _GARDEN_H_

#ifdef ENABLE_CHILLIREDIR
#include <sys/types.h>
#include <regex.h>
#endif

typedef struct pass_through_t {
  struct in_addr host;              /* IP or Network */
  struct in_addr mask;              /* Netmask */
  uint8_t proto;                    /* TCP, UDP, or ICMP */
  uint16_t port;                    /* TCP or UDP Port */
} pass_through;

#ifdef ENABLE_CHILLIREDIR
typedef struct regex_pass_through_t {
  char regex_host[512];
  char regex_path[512];
  char regex_qs[512];
  regex_t re_host;
  regex_t re_path;
  regex_t re_qs;
  char neg_host:1;
  char neg_path:1;
  char neg_qs:1;
  char reserved:5;
} regex_pass_through;

int regex_pass_throughs_from_string(regex_pass_through *ptlist, size_t ptlen, size_t *ptcnt, char *s);
#endif

int pass_through_add(pass_through *ptlist, size_t ptlen, size_t *ptcnt, pass_through *pt);
int pass_throughs_from_string(pass_through *ptlist, size_t ptlen, size_t *ptcnt, char *s);

#endif
