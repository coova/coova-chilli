/*
 * DNS library functions
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#ifndef _DNS_H
#define _DNS_H

#include "system.h"

char * dns_fullname(char *data, size_t dlen, uint8_t *res, uint8_t *opkt, size_t olen, int lvl);

int dns_copy_res(int q, 
		 uint8_t **pktp, size_t *left, 
		 uint8_t *opkt, size_t olen,
		 char *question, size_t qsize);

#endif
