/* 
 *
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
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

static int usage(char *program) {
  fprintf(stderr, "Usage: %s <unix-socket> <command> [<argument>]\n", program);
  return 1;
}

typedef struct _cmd_info {
  int type;
  char *command;
  char *desc;
} cmd_info;

static cmd_info commands[] = {
  { CMDSOCK_LIST,          "list",          NULL },
  { CMDSOCK_DHCP_LIST,     "dhcp-list",     NULL },
  { CMDSOCK_DHCP_RELEASE,  "dhcp-release",  NULL },
  { 0, NULL, NULL }
};

int main(int argc, char **argv) {
  /*
   *   chilli_query <unix-socket> <command> [<argument>]
   *   (or maybe this should get the unix-socket from the config file)
   */

  int s, len;
  struct sockaddr_un remote;
  struct cmdsock_query query;
  char line[1024], *cmd;

  if (argc < 3) return usage(argv[0]);

  cmd = argv[2];
  for (s = 0; commands[s].command; s++) {
    if (!strcmp(cmd, commands[s].command)) {
      query.type = commands[s].type;
      switch(commands[s].type) {
      case CMDSOCK_DHCP_RELEASE:
	if (argc < 4) {
	  fprintf(stderr, "%s requires a MAC address argument\n", cmd);
	  return usage(argv[0]);
	}
	else {
	  unsigned int temp[DHCP_ETH_ALEN];
	  char macstr[RADIUS_ATTR_VLEN];
	  int macstrlen;
	  int i;
	  if ((macstrlen = strlen(argv[3])) >= (RADIUS_ATTR_VLEN-1)) {
	    fprintf(stderr, "%s: bad MAC address\n", argv[3]);
	    return -1;
	  }
	  memcpy(macstr, argv[3], macstrlen);
	  macstr[macstrlen] = 0;

	  for (i=0; i<macstrlen; i++) 
	    if (!isxdigit(macstr[i])) macstr[i] = 0x20;

	  if (sscanf(macstr, "%2x %2x %2x %2x %2x %2x", 
		     &temp[0], &temp[1], &temp[2], 
		     &temp[3], &temp[4], &temp[5]) != 6) {
	    fprintf(stderr, "%s: bad MAC address\n", argv[3]);
	    return -1;
	  }
	  for(i = 0; i < DHCP_ETH_ALEN; i++) 
	    query.data.mac[i] = temp[i];
	}
	break;
      }
      break;
    }
  }
  if (!commands[s].command) {
    fprintf(stderr,"unknown command: %s\n",cmd);
    exit(1);
  }

  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, argv[1]);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(s, (struct sockaddr *)&remote, len) == -1) {
    perror("connect");
    exit(1);
  }
  
  if (write(s, &query, sizeof(query)) != sizeof(query)) {
    perror("write");
    exit(1);
  }

  while((len = read(s, line, sizeof(line)-1)) > 0) 
    write(1, line, len);

  if (len < 0) perror("read");
  shutdown(s,2);
  close(s);
  
  return 0;
}
