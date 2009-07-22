/* 
 *
 * Hash lookup function.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
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
 * see lookup3.c
 **/

#include "system.h"
#include <assert.h>

/* comment out to use Jenkins hash function */
#define SFHASH 1

uint32_t lookup(uint8_t *k,  uint32_t length,  uint32_t initval)
{
#if SFHASH
  extern uint32_t SuperFastHash(const char * data, int len, uint32_t hash);
  return SuperFastHash(k, length, initval);
#elif LITTLE_ENDIAN
  extern uint32_t hashlittle(const void *key, size_t length, uint32_t initval);
  return hashlittle(k, length, initval);
#elif BIG_ENDIAN
  extern uint32_t hashbig(const void *key, size_t length, uint32_t initval);
  return hashbig(k, length, initval);
#endif
}

