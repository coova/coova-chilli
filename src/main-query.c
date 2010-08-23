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

#define QUERY_TIMEOUT 10

struct options_t _options;

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

typedef enum _cmd_field_type {
  CMDSOCK_FIELD_NONE = 0,
  CMDSOCK_FIELD_STRING,
  CMDSOCK_FIELD_INTEGER,
  CMDSOCK_FIELD_IPV4,
} cmd_field_type;

struct cmd_arguments {
  char *name;
  cmd_field_type type;    /* 0=none, 1=string, 2=integer, 3=ip */
  int length;
  void *field;
  char *desc;
  uint8_t *flag;
  uint8_t flagbit;
};

static struct cmdsock_request request;

static struct cmd_arguments args[] = {
  { "ip", 
    CMDSOCK_FIELD_IPV4, 
    sizeof(request.data.sess.ip),
    &request.data.sess.ip,
    "IP of client to authorize", 0, 0 },
  { "sessionid",
    CMDSOCK_FIELD_STRING, 
    sizeof(request.data.sess.sessionid),
    request.data.sess.sessionid,
    "Session-id to authorize", 0, 0 },
  { "username",
    CMDSOCK_FIELD_STRING, 
    sizeof(request.data.sess.username),
    request.data.sess.username,
    "Username to use in RADIUS 'login' or authorization", 0, 0 },
  { "password",
    CMDSOCK_FIELD_STRING, 
    sizeof(request.data.sess.password),
    request.data.sess.password,
    "Password to be used for 'login' command", 0, 0 },
  { "sessiontimeout",
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.sessiontimeout),
    &request.data.sess.params.sessiontimeout,
    "Max session time (in seconds)", 0, 0 },
  { "idletimeout",
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.idletimeout),
    &request.data.sess.params.idletimeout,
    "Max idle time (in seconds)", 0, 0 },
  { "interiminterval",
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.interim_interval),
    &request.data.sess.params.interim_interval,
    "Accounting interim interval",  0, 0 },
  { "maxoctets",
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.maxtotaloctets),
    &request.data.sess.params.maxtotaloctets,
    "Max input + output octets (bytes)", 0, 0 },
  { "maxinputoctets",
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.maxinputoctets),
    &request.data.sess.params.maxinputoctets,
    "Max input octets (bytes)", 0, 0 },
  { "maxoutputoctets",
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.maxoutputoctets),
    &request.data.sess.params.maxoutputoctets,
    "Max output octets (bytes)", 0, 0 },
  { "maxbwup", 
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.bandwidthmaxup),
    &request.data.sess.params.bandwidthmaxup,
    "Max bandwidth up", 0, 0 },
  { "maxbwdown",
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.bandwidthmaxdown),
    &request.data.sess.params.bandwidthmaxdown,
    "Max bandwidth down", 0, 0 },
  { "splash",
    CMDSOCK_FIELD_STRING, 
    sizeof(request.data.sess.params.url),
    &request.data.sess.params.url,
    "Set splash page",
    &request.data.sess.params.flags, REQUIRE_UAM_SPLASH },
  { "routeidx",
    CMDSOCK_FIELD_INTEGER, 
    sizeof(request.data.sess.params.routeidx),
    &request.data.sess.params.routeidx,
    "Route interface index",  0, 0 },
  { "noacct",
    CMDSOCK_FIELD_NONE, 0, 0,
    "No accounting flag",
    &request.data.sess.params.flags, NO_ACCOUNTING },
  /* more... */
};

static int count = sizeof(args)/sizeof(struct cmd_arguments);

static int usage(char *program) {
  int i;

  fprintf(stderr, "Usage: %s [ -s <socket> ] <command> [<arguments>]\n", program);
  fprintf(stderr, "  socket = full path to UNIX domain socket (e.g. /var/run/chilli.sock)\n");

  /*  fprintf(stderr, "           TCP socket port, or ip:port, to bind to (e.g. 1999)\n"); */

  fprintf(stderr, "  Available Commands:\n    ");
  for (i=0; i < count; i++) {
    if (!commands[i].command) break;
    fprintf(stderr, "%s%s", 
	    i > 0 ? ", " : "",
	    commands[i].command);
  }
  fprintf(stderr, "\n  Available Arguments:\n");
  for (i=0; i < count; i++) {
    fprintf(stderr, "    %-18s%-7s - type: %-4s [%4d] - %s\n", 
	    args[i].name, 
	    args[i].type == CMDSOCK_FIELD_NONE ? "" :"<value>",
	    args[i].type == CMDSOCK_FIELD_NONE ? "flag" :
	    args[i].type == CMDSOCK_FIELD_STRING ? "char" :
	    args[i].type == CMDSOCK_FIELD_INTEGER ? "int" :
	    args[i].type == CMDSOCK_FIELD_IPV4 ? "ip" : "!", 
	    args[i].length, args[i].desc);
  }
  fprintf(stderr, "The ip and/or sessionid is required.\n");
  
  return 1;
}

static void timeout_alarm(int signum) {
  fprintf(stderr, "Timeout\n");
  exit(1);
}

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
  char line[1024], *cmd;
  int argidx = 1;

  struct itimerval itval;
  
  set_signal(SIGALRM, timeout_alarm);
  
  memset(&itval, 0, sizeof(itval));
  itval.it_interval.tv_sec = QUERY_TIMEOUT;
  itval.it_interval.tv_usec = 0; 
  itval.it_value.tv_sec = QUERY_TIMEOUT;
  itval.it_value.tv_usec = 0; 
  
  if (setitimer(ITIMER_REAL, &itval, NULL)) {
    log_err(errno, "setitimer() failed!");
  }
  
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
	  int pos = argidx;
	  
	  argc -= argidx;
	  
	  while(argc > 0) {
	    int i;
	    
	    for (i=0; i<count; i++) {
	      
	      if (!strcmp(argv[pos],args[i].name)) {
		
		if (args[i].flag) {
		  *(args[i].flag) |= args[i].flagbit;
		}
		
		if (argc == 1 && args[i].length) {
		  fprintf(stderr, "Argument %s requires a value\n", argv[pos]);
		  return usage(argv[0]);
		}
		
		switch(args[i].type) {
		case CMDSOCK_FIELD_NONE:
		  break;
		case CMDSOCK_FIELD_STRING:
		  strncpy(((char *)args[i].field), argv[pos+1], args[i].length-1);
		  break;
		case CMDSOCK_FIELD_INTEGER:
		  switch(args[i].length) {
		  case 1:
		    *((uint8_t *)args[i].field) |= (uint8_t)atoi(argv[pos+1]);
		    break;
		  case 2:
		    *((uint16_t *)args[i].field) |= (uint16_t)atoi(argv[pos+1]);
		    break;
		  case 4:
		    *((uint32_t *)args[i].field) |= (uint32_t)atol(argv[pos+1]);
		    break;
		  case 8:
		    *((uint64_t *)args[i].field) |= (uint64_t)atol(argv[pos+1]);
		    break;
		  }
		  break;
		case CMDSOCK_FIELD_IPV4:
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
	      return usage(argv[0]);
	    }

	    if (args[i].length) {
	      argc -= 2;
	      pos += 2;
	    } else {
	      argc --;
	      pos ++;
	    }
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
  glob(cmdsock, GLOB_DOOFFS, NULL, &globbuf);

  if (!globbuf.gl_pathc) {
    fprintf(stderr,"no cmdsock sockets: %s\n",cmdsock);
    exit(1);
  }
  
  for (i=0 ; i < globbuf.gl_pathc; i++) {
    cmdsock = globbuf.gl_pathv[i];
    if (globbuf.gl_pathc>1) {
      char header[256];
      int headerlen;
      snprintf(header, sizeof(header), "\nQuerying socket %s\n", cmdsock);
      headerlen=strlen(header);
      if (write(1, header, strlen(header))!=headerlen) {
        perror("write");
        exit(1);
      }
    }
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
  
  if (safe_write(s, &request, sizeof(request)) != sizeof(request)) {
    perror("write");
    exit(1);
  }

  while((len = safe_read(s, line, sizeof(line)-1)) > 0) {
    if (write(1, line, len) != len) {
      perror("write");
      exit(1);
    }
  }

  if (len < 0) {
    perror("read");
    exit(1);
  }

  shutdown(s, 2);
  close(s);

#ifdef HAVE_GLOB
  }
  globfree(&globbuf);
#endif
  
  return 0;
}
