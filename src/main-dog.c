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
#include "syserr.h"
#include "cmdline.h"
#include "dhcp.h"
#include "radius.h"
#include "radius_chillispot.h"
#include "radius_wispr.h"
#include "redir.h"
#include "chilli.h"
#include "options.h"
#include "cmdsock.h"

int main(int argc, char **argv) {
  struct radius_packet_t radius_pack;
  struct radius_t *radius_auth;
  struct radius_t *radius_acct;
  struct in_addr radiuslisten;
  int maxfd = 0;
  fd_set fds;
  int status;

  radiuslisten.s_addr = htonl(INADDR_ANY);

  if (radius_new(&radius_auth, &radiuslisten, 11812, 0, NULL, 0, NULL, NULL, NULL)) {
    log_err(0, "Failed to create radius");
    return -1;
  }

  if (radius_new(&radius_acct, &radiuslisten, 11813, 0, NULL, 0, NULL, NULL, NULL)) {
    log_err(0, "Failed to create radius");
    return -1;
  }

  while (1) {
    FD_ZERO(&fds);
    FD_SET(maxfd = radius_auth->fd, &fds);
    FD_SET(maxfd = radius_acct->fd, &fds);
    
    switch (status = select(maxfd + 1, &fds, NULL, NULL, NULL)) {
    case -1:
      log_err(errno, "select() returned -1!");
      break;  
    case 0:
    default:
      break;
    }
    
    if (status > 0) {
      struct sockaddr_in addr;
      socklen_t fromlen = sizeof(addr);

      if (FD_ISSET(radius_auth->fd, &fds)) {
	/*
	 *    ---> Authentication
	 */

	printf("here with auth\n");

	if ((status = recvfrom(radius_auth->fd, &radius_pack, sizeof(radius_pack), 0, 
			       (struct sockaddr *) &addr, &fromlen)) <= 0) {
	  log_err(errno, "recvfrom() failed");
	  return -1;
	}

      }
      if (FD_ISSET(radius_acct->fd, &fds)) {
	/*
	 *    ---> Accounting
	 */

	printf("here with acct\n");

	if ((status = recvfrom(radius_acct->fd, &radius_pack, sizeof(radius_pack), 0, 
			       (struct sockaddr *) &addr, &fromlen)) <= 0) {
	  log_err(errno, "recvfrom() failed");
	  return -1;
	}
      }
    }
  }
}
