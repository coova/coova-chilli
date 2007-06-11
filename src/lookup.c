/* 
 *
 * Hash lookup function.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (c) 2007 David Bird <david@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

/**
 * lookup()
 * see lookup3.c
 **/

#include "system.h"
#include <assert.h>

extern uint32_t hashlittle(const void *key, size_t length, uint32_t initval);
extern uint32_t hashbig(const void *key, size_t length, uint32_t initval);

uint32_t lookup(uint8_t *k,  uint32_t length,  uint32_t initval)
{
#if LITTLE_ENDIAN
  return hashlittle(k, length, initval);
#endif 
#if BIG_ENDIAN
  return hashbig(k, length, initval);
#endif
}

