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


#ifndef _IPHASH_H
#define _IPHASH_H

#include "ippool.h"

/* IP hash functions are used to generate a hash table of IP addresses.
   The functions build on ippool.c.
   ippool_getip() is used to check if an address is in the hash table. */

/* Create new address pool */
extern 
int iphash_new(struct ippool_t **this, struct ippoolm_t *list, int listsize);

/* Delete existing address pool */
extern int iphash_free(struct ippool_t *this);


#endif	/* !_IPHASH_H */
