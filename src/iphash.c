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
 
#include <sys/types.h>
#include <netinet/in.h> /* in_addr */
#include <stdlib.h>     /* calloc */
#include <stdio.h>      /* sscanf */

#include "iphash.h"

/* Create new address pool hash */
int iphash_new(struct ippool_t **this, struct ippoolm_t *list, int listsize) {

  int i;

  if (!(*this = calloc(sizeof(struct ippool_t), 1))) {
    /* Failed to allocate memory for iphash */
    return -1;
  }
  
  (*this)->listsize = listsize;
  (*this)->member = list;

  /* Determine log2 of hashsize */
  for ((*this)->hashlog = 0; 
       ((1 << (*this)->hashlog) < listsize);
       (*this)->hashlog++);
  
  /* Determine hashsize */
  (*this)->hashsize = 1 << (*this)->hashlog; /* Fails if mask=0: All Internet*/
  (*this)->hashmask = (*this)->hashsize -1;
  
  /* Allocate hash table */
  if (!((*this)->hash = calloc(sizeof(struct ippoolm_t), (*this)->hashsize))){
    /* Failed to allocate memory for hash members in iphash */
    return -1;
  }
  
  for (i = 0; i<listsize; i++) {
    
    (*this)->member[i].inuse = 1; /* TODO */
    ippool_hashadd(*this, &(*this)->member[i]);
  }

  return 0;
}

/* Delete existing address pool */
int iphash_free(struct ippool_t *this) {
  free(this->hash);
  free(this);
  return 0; /* Always OK */
}
