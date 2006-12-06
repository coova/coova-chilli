/* This file is free software; you can redistribute it and/or modify */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation; either version 2, or (at your option) */
/* any later version. */

/* This file is distributed in the hope that it will be useful, */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the */
/* GNU General Public License for more details. */

/* You should have received a copy of the GNU General Public License */
/* along with GNU Emacs; see the file COPYING.  If not, write to */
/* the Free Software Foundation, Inc., 59 Temple Place - Suite 330, */
/* Boston, MA 02111-1307, USA. */

/* Copyright (C) 2004 Ian Zimmerman */

/* $Id: getline.c,v 1.3 2004/05/18 22:45:18 summerisle Exp $ */

#include "../config.h"
#ifndef HAVE_GETLINE
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

#define GETLINE_BUFSIZE 4096

ssize_t
getline (char** lineptr, size_t* n, FILE* stream)
{
  char* lptr1;
  size_t nn;
  int c;

  if (*lineptr == NULL && n == NULL)
    {
      lptr1 = malloc (GETLINE_BUFSIZE);
      if (lptr1 == NULL) return EOF;
      nn = GETLINE_BUFSIZE;
    }
  else
    {
      lptr1 = *lineptr;
      nn = *n;
    }
  c = fgetc (stream);
  if (c == EOF) return EOF;
  {
    int offset;

    offset = 0;
    while (c != EOF)
      {
        if (offset >= nn - 1)
          {
            char* lptr2;
            lptr2 = realloc (lptr1, 2 * nn);
            if (lptr2 == NULL) return EOF;
            lptr1 = lptr2;
            nn *= 2;
          }
        lptr1[offset++] = (char)c;
        if (c == '\n') break;
        c = fgetc (stream);
      }
    lptr1[offset] = '\0';
    *lineptr = lptr1;
    *n = nn;
    return offset;
  }  
}
#endif
