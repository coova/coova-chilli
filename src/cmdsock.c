/* 
 * CoovaChilli: A Wireless LAN Access Point Controller.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include "system.h"
#include "redir.h"
#include "syserr.h"
#include "radius.h"
#include "dhcp.h"
#include "chilli.h"
#include "cmdline.h"
#include "options.h"
#include "cmdsock.h"

int
cmdsock_init() {
  struct sockaddr_un local;
  int cmdsock;
  
  if ((cmdsock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    log_err(errno, "could not allocate UNIX Socket!");
  } else {
    local.sun_family = AF_UNIX;

    strcpy(local.sun_path, options()->cmdsocket);
    unlink(local.sun_path);

    if (bind(cmdsock, (struct sockaddr *)&local, 
	     sizeof(struct sockaddr_un)) == -1) {
      log_err(errno, "could bind UNIX Socket!");
      close(cmdsock);
      cmdsock = -1;
    } else {
      if (listen(cmdsock, 5) == -1) {
	log_err(errno, "could listen to UNIX Socket!");
	close(cmdsock);
	cmdsock = -1;
      }
    }
  }

  return cmdsock;
}
