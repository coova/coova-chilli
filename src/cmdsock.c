/* 
 * chilli - A Wireless LAN Access Point Controller.
 * Copyright (c) 2007 David Bird <david@coova.com>
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
#include "dhcp.h"
#include "chilli.h"
#include "cmdline.h"
#include "options.h"
#include "cmdsock.h"


int
cmdsock_init() {
  struct sockaddr_un local;
  size_t len;
  int cmdsock;
  
  if ((cmdsock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    log_err(errno, "could not allocate UNIX Socket!");
  } else {
    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, options.cmdsocket);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(cmdsock, (struct sockaddr *)&local, len) == -1) {
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
