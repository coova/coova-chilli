/* 
 *
 * Hash lookup function.
 * Copyright (C) 2003, 2004 Mondru AB.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

/**
 * lookup()
 * Generates a 32 bit hash.
 * Based on public domain code by Bob Jenkins
 * It should be one of the best hash functions around in terms of both
 * statistical properties and speed. It is NOT recommended for cryptographic
 * purposes.
 **/

#ifndef _LOOKUP_H
#define _LOOKUP_H

uint32_t lookup(uint8_t *k, size_t length, uint32_t level);

#endif	/* !_LOOKUP_H */
