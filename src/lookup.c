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
  return SuperFastHash((const char*)k, length, initval);
#elif LITTLE_ENDIAN
  extern uint32_t hashlittle(const void *key, size_t length, uint32_t initval);
  return hashlittle(k, length, initval);
#elif BIG_ENDIAN
  extern uint32_t hashbig(const void *key, size_t length, uint32_t initval);
  return hashbig(k, length, initval);
#endif
}

