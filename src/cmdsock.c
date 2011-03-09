/* 
 * Copyright (C) 2007-2011 Coova Technologies, LLC. <support@coova.com>
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

#include "chilli.h"

int
cmdsock_init() {
  struct sockaddr_un local;
  int cmdsock;
  
  if ((cmdsock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {

    log_err(errno, "could not allocate UNIX Socket!");

  } else {

    local.sun_family = AF_UNIX;

    strcpy(local.sun_path, _options.cmdsocket);
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
      } else {
	if (_options.uid) {
	  if (chown(_options.cmdsocket, _options.uid, _options.gid)) {
	    log_err(errno, "could not chown() %s",
		    _options.cmdsocket);
	  }
	}
      }
    }
  }

  return cmdsock;
}

