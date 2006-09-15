/* 
 *
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2006 PicoPoint B.V.
 * Copyright (c) 2006 Coova Technologies Ltd
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include "system.h"

extern int chilli_main(int argc, char **argv);

int main(int argc, char **argv)
{
  int ret;
#ifdef MTRACE
  mtrace();  /* Turn on mtrace function */
#endif
  ret = chilli_main(argc, argv);
#ifdef MTRACE
  muntrace();  /* Turn off mtrace function */
#endif
  return ret;
}
