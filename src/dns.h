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

#ifndef _DNS_H
#define _DNS_H

#include "system.h"

int dns_getname(uint8_t **pktp, size_t *left, char *name, size_t namesz, size_t *nameln);

char * dns_fullname(char *data, size_t dlen, uint8_t *res, uint8_t *opkt, size_t olen, int lvl);

int dns_copy_res(int q, 
		 uint8_t **pktp, size_t *left, 
		 uint8_t *opkt, size_t olen,
		 char *question, size_t qsize);

#endif
