/* 
 * Copyright (C) 2006 PicoPoint B.V.
 * Copyright (C) 2007-2010 Coova Technologies, LLC. <support@coova.com>
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

#define MAIN_FILE

#include "chilli.h"

#ifdef HAVE_GLOB
#include <glob.h>
#endif

struct options_t _options;

static int usage(char *program) {
  fprintf(stderr, "Usage: %s [ -s <socket> ] <command> [<argument>]\n", program);
  fprintf(stderr, "  socket = full path to UNIX domain socket (e.g. /var/run/chilli.sock)\n");
  /*  fprintf(stderr, "           TCP socket port, or ip:port, to bind to (e.g. 1999)\n"); */
  return 1;
}

typedef struct _cmd_info {
  int type;
  char *command;
  char *desc;
} cmd_info;

static cmd_info commands[] = {
  { CMDSOCK_LIST,          "list",          NULL },
  { CMDSOCK_LIST_IPPOOL,   "listippool",    NULL },
  { CMDSOCK_ENTRY_FOR_IP,  "listip",        NULL },
  { CMDSOCK_ENTRY_FOR_MAC, "listmac",       NULL },
  { CMDSOCK_ROUTE,         "route",         NULL },
  { CMDSOCK_ROUTE_GW,      "routegw",       NULL },
  { CMDSOCK_RELOAD,        "reload",        NULL },
  { CMDSOCK_DHCP_LIST,     "dhcp-list",     NULL },
  { CMDSOCK_DHCP_RELEASE,  "dhcp-release",  NULL },
  { CMDSOCK_AUTHORIZE,     "authorize",     NULL },
  { CMDSOCK_LOGIN,         "login",         NULL },
  { CMDSOCK_DHCP_RELEASE,  "logout",        NULL },
  { CMDSOCK_DHCP_RELEASE,  "logoff",        NULL },
  { CMDSOCK_DHCP_DROP,     "drop",          NULL },
  { CMDSOCK_DHCP_DROP,     "block",         NULL },
#ifdef ENABLE_STATFILE
  { CMDSOCK_STATUSFILE,    "statusfile",    NULL },
#endif
  { 0, NULL, NULL }
};

int main(int argc, char **argv) {
  /*
   *   chilli_query [ -s <unix-socket> ] <command> [<argument>]
   *   (or maybe this should get the unix-socket from the config file)
   */

#ifdef HAVE_GLOB
  char *cmdsock = DEFSTATEDIR"/chilli*.sock";
  glob_t globbuf;
  int i;
#else
  char *cmdsock = DEFSTATEDIR"/chilli.sock";
#endif
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
  } 
  
  memset(&request,0,sizeof(request));
  
  while (argidx < argc && *argv[argidx] == '-') {
    if (!strcmp(argv[argidx], "-s")) {
      argidx++;
      if (argidx >= argc) return usage(argv[0]);
      cmdsock = argv[argidx++];
    } else if (!strcmp(argv[argidx], "-json")) {
      request.options |= CMDSOCK_OPT_JSON;
      argidx++;
    }
  }
  
  if (argidx >= argc) return usage(argv[0]);
  
  cmd = argv[argidx++];
  for (s = 0; commands[s].command; s++) {
    if (!strcmp(cmd, commands[s].command)) {
      request.type = commands[s].type;
      switch(request.type) {
      case CMDSOCK_LOGIN:
      case CMDSOCK_AUTHORIZE:
	{
	  struct arguments {
	    char *name;
	    int type;    /* 0=string, 1=integer, 2=ip */
	    int length;
	    void *field;
	    char *desc;
	    uint8_t *flag;
	    char flagbit;
	  } args[] = {
	    { "ip", 2, 
	      sizeof(request.data.sess.ip),
	      &request.data.sess.ip,
	      "IP of client to authorize",0,0 },
	    { "sessionid", 0, 
	      sizeof(request.data.sess.sessionid),
	      request.data.sess.sessionid,
	      "Session-id to authorize",0,0 },
	    { "username", 0, 
	      sizeof(request.data.sess.username),
	      request.data.sess.username,
	      "Username to use in RADIUS 'login' or authorization",0,0 },
	    { "password", 0, 
	      sizeof(request.data.sess.password),
	      request.data.sess.password,
	      "Password to be used for 'login' command",0,0 },
	    { "sessiontimeout", 1, 
	      sizeof(request.data.sess.params.sessiontimeout),
	      &request.data.sess.params.sessiontimeout,
	      "Max session time (in seconds)",0,0 },
	    { "idletimeout", 1, 
	      sizeof(request.data.sess.params.idletimeout),
	      &request.data.sess.params.idletimeout,
	      "Max idle time (in seconds)",0,0 },
	    { "maxoctets", 1, 
	      sizeof(request.data.sess.params.maxtotaloctets),
	      &request.data.sess.params.maxtotaloctets,
	      "Max input + output octets (bytes)",0,0 },
	    { "maxinputoctets", 1, 
	      sizeof(request.data.sess.params.maxinputoctets),
	      &request.data.sess.params.maxinputoctets,
	      "Max input octets (bytes)",0,0 },
	    { "maxoutputoctets", 1, 
	      sizeof(request.data.sess.params.maxoutputoctets),
	      &request.data.sess.params.maxoutputoctets,
	      "Max output octets (bytes)",0,0 },
	    { "maxbwup", 1, 
	      sizeof(request.data.sess.params.bandwidthmaxup),
	      &request.data.sess.params.bandwidthmaxup,
	      "Max bandwidth up",0,0 },
	    { "maxbwdown", 1, 
	      sizeof(request.data.sess.params.bandwidthmaxdown),
	      &request.data.sess.params.bandwidthmaxdown,
	      "Max bandwidth down",0,0 },
	    { "splash", 0, 
	      sizeof(request.data.sess.params.url),
	      &request.data.sess.params.url,
	      "Set splash page",
	      &request.data.sess.params.flags, REQUIRE_UAM_SPLASH },
	    { "routeidx", 1, 
	      sizeof(request.data.sess.params.routeidx),
	      &request.data.sess.params.routeidx,
	      "Route interface index",  0, 0 },
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
		
		if (args[i].flag) {
		  *(args[i].flag) |=args[i].flagbit;
		}
		
		switch(args[i].type) {
		case 0:
		  strncpy(((char *)args[i].field), argv[pos+1], args[i].length-1);
		  break;
		case 1:
		  switch(args[i].length) {
		  case 1:
		    *((uint8_t *)args[i].field) = (uint8_t)atoi(argv[pos+1]);
		    break;
		  case 2:
		    *((uint16_t *)args[i].field) = (uint16_t)atoi(argv[pos+1]);
		    break;
		  case 4:
		    *((uint32_t *)args[i].field) = (uint32_t)atol(argv[pos+1]);
		    break;
		  case 8:
		    *((uint64_t *)args[i].field) = (uint64_t)atol(argv[pos+1]);
		    break;
		  }
		  break;
		case 2:
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
      case CMDSOCK_ENTRY_FOR_IP:
	{
	  /* Test for a valid ip argument. */
  	  if (argc < argidx+1) {
  	    fprintf(stderr, "%s requires an IP address argument\n", cmd);
  	    return usage(argv[0]);
  	  }
	  
	  if (!inet_aton(argv[argidx], &request.data.sess.ip)) {
	    fprintf(stderr, "Invalid IP Address: %s\n", argv[argidx]);
	    return usage(argv[0]);
	  }
	}
	break;
      case CMDSOCK_DHCP_DROP:
      case CMDSOCK_DHCP_RELEASE:
      case CMDSOCK_ENTRY_FOR_MAC:
	{
	  unsigned int temp[PKT_ETH_ALEN];
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
	  
	  for (i = 0; i < PKT_ETH_ALEN; i++) 
	    request.data.mac[i] = temp[i];
	  
	  /* do another switch to pick up param configs for authorize */
	}
	break;
      case CMDSOCK_ROUTE:
      case CMDSOCK_ROUTE_GW:
	{
	  unsigned int temp[PKT_ETH_ALEN];
	  char macstr[RADIUS_ATTR_VLEN];
	  int macstrlen;
	  int i;
	  
	  if (argc < argidx + 2) {
	    break;
	  }
	  
	  if ((macstrlen = strlen(argv[argidx])) >= (RADIUS_ATTR_VLEN-1)) {
	    fprintf(stderr, "%s: bad MAC address\n", argv[argidx]);
	    break;
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
	    break;
	  }

	  for (i = 0; i < PKT_ETH_ALEN; i++) 
	    request.data.mac[i] = temp[i];

	  argidx++;
	  request.data.sess.params.routeidx = atoi(argv[argidx]);

	  if (request.type != CMDSOCK_ROUTE_GW)
	    request.type = CMDSOCK_ROUTE_SET;

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
  
#ifdef HAVE_GLOB
  globbuf.gl_offs = 0;
  glob(cmdsock,GLOB_DOOFFS,NULL,&globbuf);
  
  for (i=0 ; i < globbuf.gl_pathc; i++) {
    cmdsock = globbuf.gl_pathv[i];
#endif

  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, cmdsock);

#if defined (__FreeBSD__)  || defined (__APPLE__) || defined (__OpenBSD__)
  remote.sun_len = strlen(remote.sun_path) + 1;
#endif

  len = offsetof(struct sockaddr_un, sun_path) + strlen(remote.sun_path);

  if (connect(s, (struct sockaddr *)&remote, len) == -1) {
    perror("connect");
    exit(1);
  }
  
  if (write(s, &request, sizeof(request)) != sizeof(request)) {
    perror("write");
    exit(1);
  }

  while((len = read(s, line, sizeof(line)-1)) > 0) 
    if (write(1, line, len) != len)
      perror("write");

  if (len < 0) 
    perror("read");

  shutdown(s,2);
  close(s);

#ifdef HAVE_GLOB
  }
  globfree(&globbuf);
#endif
  
  return 0;
}
