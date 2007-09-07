/* 
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
 * Copyright (C) 2006 PicoPoint B.V.
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
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
  fprintf(stderr, "Usage: %s [ -s <socket> ] <command> [<argument>]\n", program);
  fprintf(stderr, "  socket = full path to UNIX domain socket (e.g. /var/run/chilli.sock)\n");
  fprintf(stderr, "           TCP socket port, or ip:port, to bind to (e.g. 1999)\n");
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
  { CMDSOCK_AUTHORIZE,     "authorize",     NULL },
  { CMDSOCK_DHCP_RELEASE,  "logout",        NULL },
  { CMDSOCK_DHCP_RELEASE,  "logoff",        NULL },
  { 0, NULL, NULL }
};

int main(int argc, char **argv) {
  /*
   *   chilli_query [ -s <unix-socket> ] <command> [<argument>]
   *   (or maybe this should get the unix-socket from the config file)
   */

  char *cmdsock = DEFCMDSOCK;
  int s, len;
  struct sockaddr_un remote;
  struct cmdsock_request request;
  char line[1024], *cmd;
  int argidx = 1;

  if (argc < 2) return usage(argv[0]);

  if (*argv[argidx] == '/') {
    /* for backward support, ignore a unix-socket given as first arg */
    if (argc < 3) return usage(argv[0]);
    cmdsock = argv[argidx++];
  } else if (!strcmp(argv[argidx], "-s")) {
    if (argc < 4) return usage(argv[0]);
    argidx++;
    cmdsock = argv[argidx++];
  }

  memset(&request,0,sizeof(request));

  cmd = argv[argidx++];
  for (s = 0; commands[s].command; s++) {
    if (!strcmp(cmd, commands[s].command)) {
      request.type = commands[s].type;
      switch(commands[s].type) {
      case CMDSOCK_AUTHORIZE:
	{
	  struct arguments {
	    char *name;
	    int type;    /* 0=string, 1=long, 2=short, 3=ip */
	    int length;
	    void *field;
	    char *desc;
	  } args[] = {
	    { "ip", 3, 
	      sizeof(request.data.sess.ip),
	      &request.data.sess.ip,
	      "IP of client to authorize" },
	    { "sessionid", 0, 
	      sizeof(request.data.sess.sessionid),
	      request.data.sess.sessionid,
	      "Session-id to authorize" },
	    { "username", 0, 
	      sizeof(request.data.sess.username),
	      request.data.sess.username,
	      "Username to use in RADIUS Accounting" },
	    { "sessiontimeout", 1, 
	      sizeof(request.data.sess.params.sessiontimeout),
	      &request.data.sess.params.sessiontimeout,
	      "Max session time (in seconds)" },
	    { "maxoctets", 1, 
	      sizeof(request.data.sess.params.maxtotaloctets),
	      &request.data.sess.params.maxtotaloctets,
	      "Max up/down octets (bytes)" },
	    { "maxbwup", 1, 
	      sizeof(request.data.sess.params.bandwidthmaxup),
	      &request.data.sess.params.bandwidthmaxup,
	      "Max bandwidth up" },
	    { "maxbwdown", 1, 
	      sizeof(request.data.sess.params.bandwidthmaxdown),
	      &request.data.sess.params.bandwidthmaxdown,
	      "Max bandwidth down" },
	    /* more... */
	  };
	  int count = sizeof(args)/sizeof(struct arguments);
	  int pos = argidx;
	  argc -= argidx;
	  while(argc > 0) {
	    int i;

	    for (i=0; i<count; i++) {

	      if (!strcmp(argv[pos],args[i].name)) {

		if (argc == 1) {
		  fprintf(stderr, "Argument %s requires a value\n", argv[pos]);
		  return usage(argv[0]);
		}
	  
		switch(args[i].type) {
		case 0:
		  strncpy(((char *)args[i].field), argv[pos+1], args[i].length-1);
		  break;
		case 1:
		  *((unsigned long *)args[i].field) = atoi(argv[pos+1]);
		  break;
		case 2:
		  *((unsigned short *)args[i].field) = atoi(argv[pos+1]);
		  break;
		case 3:
		  if (!inet_aton(argv[pos+1], ((struct in_addr *)args[i].field))) {
		    fprintf(stderr, "Invalid IP Address: %s\n", argv[pos+1]);
		    return usage(argv[0]);
		  }
		  break;
		}
		break;
	      }
	    }

	    if (i == count) {
	      fprintf(stderr, "Unknown argument: %s\n", argv[pos]);
	      fprintf(stderr, "Use:\n");
	      for (i=0; i<count; i++) {
		fprintf(stderr, "  %-15s<value>  - type: %-6s - %s\n", 
			args[i].name, 
			args[i].type == 0 ? "string" :
			args[i].type == 1 ? "long" :
			args[i].type == 2 ? "int" :
			args[i].type == 3 ? "ip" :
			"unknown", args[i].desc);
	      }
	      fprintf(stderr, "The ip and/or sessionid is required.\n");
	      return usage(argv[0]);
	    }

	    argc -= 2;
	    pos += 2;
	  }
	}
	break;
      case CMDSOCK_DHCP_RELEASE:
	{
	  unsigned int temp[DHCP_ETH_ALEN];
	  char macstr[RADIUS_ATTR_VLEN];
	  int macstrlen;
	  int i;

	  if (argc < argidx+1) {
	    fprintf(stderr, "%s requires a MAC address argument\n", cmd);
	    return usage(argv[0]);
	  }
	  
	  if ((macstrlen = strlen(argv[argidx])) >= (RADIUS_ATTR_VLEN-1)) {
	    fprintf(stderr, "%s: bad MAC address\n", argv[argidx]);
	    return -1;
	  }

	  memcpy(macstr, argv[argidx], macstrlen);
	  macstr[macstrlen] = 0;

	  for (i=0; i<macstrlen; i++) 
	    if (!isxdigit(macstr[i])) 
	      macstr[i] = 0x20;

	  if (sscanf(macstr, "%2x %2x %2x %2x %2x %2x", 
		     &temp[0], &temp[1], &temp[2], 
		     &temp[3], &temp[4], &temp[5]) != 6) {
	    fprintf(stderr, "%s: bad MAC address\n", argv[argidx]);
	    return -1;
	  }

	  for (i = 0; i < DHCP_ETH_ALEN; i++) 
	    request.data.mac[i] = temp[i];

	  /* do another switch to pick up param configs for authorize */
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
  strcpy(remote.sun_path, cmdsock);
  len = strlen(remote.sun_path) + sizeof(remote.sun_family);
  if (connect(s, (struct sockaddr *)&remote, len) == -1) {
    perror("connect");
    exit(1);
  }
  
  if (write(s, &request, sizeof(request)) != sizeof(request)) {
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
