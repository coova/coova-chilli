/* 
 *
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2006 PicoPoint B.V.
 * Copyright (c) 2007 David Bird <david@coova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include "system.h"
#include "tun.h"
#include "ippool.h"
#include "radius.h"
#include "radius_wispr.h"
#include "radius_chillispot.h"
#include "redir.h"
#include "syserr.h"
#include "dhcp.h"
#include "cmdline.h"
#include "chilli.h"
#include "options.h"
#include "cmdsock.h"
#include "net.h"

struct tun_t *tun;                /* TUN instance            */
struct ippool_t *ippool;          /* Pool of IP addresses */
struct radius_t *radius;          /* Radius client instance */
struct dhcp_t *dhcp = NULL;       /* DHCP instance */
struct redir_t *redir = NULL;     /* Redir instance */

int connections=0;
struct app_conn_t *firstfreeconn=0; /* First free in linked list */
struct app_conn_t *lastfreeconn=0;  /* Last free in linked list */
struct app_conn_t *firstusedconn=0; /* First used in linked list */
struct app_conn_t *lastusedconn=0;  /* Last used in linked list */

extern struct app_conn_t admin_session;

time_t mainclock;
time_t checktime;
time_t rereadtime;

static int keep_going = 1;
/*static int do_timeouts = 1;*/
static int do_sighup = 0;

/* Forward declarations */
static int acct_req(struct app_conn_t *conn, uint8_t status_type);

/* Fireman catches falling childs and eliminates zombies */
static void fireman(int signum) { 
  while (wait3(NULL, WNOHANG, NULL) > 0);
}

/* Termination handler for clean shutdown */
static void termination_handler(int signum) {
  if (options.debug) log_dbg("SIGTERM received!\n");
  keep_going = 0;
}

/* Alarm handler for general house keeping 
void static alarm_handler(int signum) {
  if (options.debug) log_dbg("SIGALRM received!\n");
  do_timeouts = 1;
}*/

/* Sighup handler for rereading configuration file */
static void sighup_handler(int signum) {
  if (options.debug) log_dbg("SIGHUP received!\n");
  do_sighup = 1;
}


static void set_sessionid(struct app_conn_t *appconn) {
  snprintf(appconn->s_state.sessionid, sizeof(appconn->s_state.sessionid), 
	   "%.8x%.8x", (int) mainclock, appconn->unit);
  /*log_dbg("!!!! RESET CLASSLEN !!!!");*/
  appconn->s_state.redir.classlen = 0;
}

/* Used to write process ID to file. Assume someone else will delete */
void static log_pid(char *pidfile) {
  FILE *file;
  mode_t oldmask;

  oldmask = umask(022);
  file = fopen(pidfile, "w");
  umask(oldmask);
  if(!file) return;
  fprintf(file, "%d\n", getpid());
  fclose(file);
}

#ifdef LEAKY_BUCKET
/* Perform leaky bucket on up- and downlink traffic */
int static leaky_bucket(struct app_conn_t *conn, uint64_t octetsup, uint64_t octetsdown) {
  
  time_t timenow = mainclock;
  uint64_t timediff; 
  int result = 0;

  timediff = timenow - conn->s_state.last_time;

  if (options.debug && (conn->s_params.bandwidthmaxup || 
			conn->s_params.bandwidthmaxdown))
    log_dbg("Leaky bucket timediff: %lld, bucketup: %lld, bucketdown: %lld, up: %lld, down: %lld", 
	    timediff, conn->s_state.bucketup, conn->s_state.bucketdown, 
	    octetsup, octetsdown);

  if (conn->s_params.bandwidthmaxup) {
    /* Subtract what the leak since last time we visited */
    if (conn->s_state.bucketup > ((timediff * conn->s_params.bandwidthmaxup) / 8)) {
      conn->s_state.bucketup -= (timediff * conn->s_params.bandwidthmaxup) / 8;
    }
    else {
      conn->s_state.bucketup = 0;
    }
    
    if ((conn->s_state.bucketup + octetsup) > conn->s_state.bucketupsize) {
      if (options.debug) log_dbg("Leaky bucket deleting uplink packet");
      result = -1;
    }
    else {
      conn->s_state.bucketup += octetsup;
    }
  }

  if (conn->s_params.bandwidthmaxdown) {
    if (conn->s_state.bucketdown > ((timediff * conn->s_params.bandwidthmaxdown) / 8)) {
      conn->s_state.bucketdown -= (timediff * conn->s_params.bandwidthmaxdown) / 8;
    }
    else {
      conn->s_state.bucketdown = 0;
    }
    
    if ((conn->s_state.bucketdown + octetsdown) > conn->s_state.bucketdownsize) {
      if (options.debug) log_dbg("Leaky bucket deleting downlink packet");
      result = -1;
    }
    else {
      conn->s_state.bucketdown += octetsdown;
    }
  }

  conn->s_state.last_time = timenow;
    
  return result;
}
#endif


/* Run external script */
#define VAL_STRING   0
#define VAL_IN_ADDR  1
#define VAL_MAC_ADDR 2
#define VAL_ULONG    3
#define VAL_ULONG64  4
#define VAL_USHORT   5

int set_env(char *name, char type, void *value, int len) {
  char *v=0;
  char s[1024];

  memset(s,0,sizeof(s));

  switch(type) {

  case VAL_IN_ADDR:
    strncpy(s, inet_ntoa(*(struct in_addr *)value), sizeof(s)); 
    v = s;
    break;

  case VAL_MAC_ADDR:
    {
      uint8_t * mac = (uint8_t*)value;
      snprintf(s, sizeof(s)-1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
      v = s;
    }
    break;

  case VAL_ULONG:
    snprintf(s, sizeof(s)-1, "%ld", (long int)*(uint32_t *)value);
    v = s;
    break;

  case VAL_ULONG64:
    snprintf(s, sizeof(s)-1, "%ld", (long int)*(uint64_t *)value);
    v = s;
    break;

  case VAL_USHORT:
    snprintf(s, sizeof(s)-1, "%d", (int)(*(uint16_t *)value));
    v = s;
    break;

  case VAL_STRING:
    if (len != 0) {
      if (len >= sizeof(s)) {
	return -1;
      }
      strncpy(s, (char*)value, len);
      s[len] = 0;
      v = s;
    } else {
      v = (char*)value;
    }
    break;
  }

  if (name != NULL && v != NULL) {
    if (setenv(name, v, 1) != 0) {
      log_err(errno, "setenv(%s, %s, 1) did not return 0!", name, v);
      return -1;
    }
  }

  return 0;
}

int runscript(struct app_conn_t *appconn, char* script) {  
  int status;

  if ((status = fork()) < 0) {
    log_err(errno,
	    "fork() returned -1!");
    return 0;
  }

  if (status > 0) { /* Parent */
    return 0; 
  }

/*
  if (clearenv() != 0) {
    log_err(errno,
	    "clearenv() did not return 0!");
    exit(0);
  }
*/

  set_env("DEV", VAL_STRING, tun->_interfaces[0].devname, 0);
  set_env("NET", VAL_IN_ADDR, &appconn->net, 0);
  set_env("MASK", VAL_IN_ADDR, &appconn->mask, 0);
  set_env("ADDR", VAL_IN_ADDR, &appconn->ourip, 0);
  set_env("USER_NAME", VAL_STRING, appconn->s_state.redir.username, 0);
  set_env("NAS_IP_ADDRESS", VAL_IN_ADDR,&options.radiuslisten, 0);
  set_env("SERVICE_TYPE", VAL_STRING, "1", 0);
  set_env("FRAMED_IP_ADDRESS", VAL_IN_ADDR, &appconn->hisip, 0);
  set_env("FILTER_ID", VAL_STRING, appconn->s_params.filteridbuf, 0);
  set_env("STATE", VAL_STRING, appconn->s_state.redir.statebuf, appconn->s_state.redir.statelen);
  set_env("CLASS", VAL_STRING, appconn->s_state.redir.classbuf, appconn->s_state.redir.classlen);
  set_env("SESSION_TIMEOUT", VAL_ULONG64, &appconn->s_params.sessiontimeout, 0);
  set_env("IDLE_TIMEOUT", VAL_ULONG, &appconn->s_params.idletimeout, 0);
  set_env("CALLING_STATION_ID", VAL_MAC_ADDR, appconn->hismac, 0);
  set_env("CALLED_STATION_ID", VAL_MAC_ADDR, appconn->ourmac, 0);
  set_env("NAS_ID", VAL_STRING, options.radiusnasid, 0);
  set_env("NAS_PORT_TYPE", VAL_STRING, "19", 0);
  set_env("ACCT_SESSION_ID", VAL_STRING, appconn->s_state.sessionid, 0);
  set_env("ACCT_INTERIM_INTERVAL", VAL_USHORT, &appconn->s_params.interim_interval, 0);
  set_env("WISPR_LOCATION_ID", VAL_STRING, options.radiuslocationid, 0);
  set_env("WISPR_LOCATION_NAME", VAL_STRING, options.radiuslocationname, 0);
  set_env("WISPR_BANDWIDTH_MAX_UP", VAL_ULONG, &appconn->s_params.bandwidthmaxup, 0);
  set_env("WISPR_BANDWIDTH_MAX_DOWN", VAL_ULONG, &appconn->s_params.bandwidthmaxdown, 0);
  /*set_env("WISPR-SESSION_TERMINATE_TIME", VAL_USHORT, &appconn->sessionterminatetime, 0);*/
  set_env("CHILLISPOT_MAX_INPUT_OCTETS", VAL_ULONG64, &appconn->s_params.maxinputoctets, 0);
  set_env("CHILLISPOT_MAX_OUTPUT_OCTETS", VAL_ULONG64, &appconn->s_params.maxoutputoctets, 0);
  set_env("CHILLISPOT_MAX_TOTAL_OCTETS", VAL_ULONG64, &appconn->s_params.maxtotaloctets, 0);

  if (execl(script, script, (char *) 0) != 0) {
      log_err(errno,
	      "execl() did not return 0!");
      exit(0);
  }

  exit(0);
}

/***********************************************************
 *
 * Functions handling uplink protocol authentication.
 * Called in response to radius access request response.
 *
 ***********************************************************/

static int newip(struct ippoolm_t **ipm, struct in_addr *hisip) {
  if (ippool_newip(ippool, ipm, hisip, 1)) {
    if (ippool_newip(ippool, ipm, hisip, 0)) {
      log_err(0, "Failed to allocate either static or dynamic IP address");
      return -1;
    }
  }
  return 0;
}


/* 
 * A few functions to manage connections 
 */

int static initconn()
{
  checktime = rereadtime = mainclock;
  return 0;
}

int static newconn(struct app_conn_t **conn) {
  int n;

  if (!firstfreeconn) {

    if (connections == APP_NUM_CONN) {
      log_err(0, "reached max connections!");
      return -1;
    }

    n = ++connections;

    if (!(*conn = calloc(1, sizeof(struct app_conn_t)))) {
      log_err(0, "Out of memory!");
      return -1;
    }

  } else {

    *conn = firstfreeconn;
    n = (*conn)->unit;

    /* Remove from link of free */
    if (firstfreeconn->next) {
      firstfreeconn->next->prev = NULL;
      firstfreeconn = firstfreeconn->next;
    }
    else { /* Took the last one */
      firstfreeconn = NULL; 
      lastfreeconn = NULL;
    }

    /* Initialise structures */
    memset(*conn, 0, sizeof(struct app_conn_t));
  }

  /* Insert into link of used */
  if (firstusedconn) {
    firstusedconn->prev = *conn;
    (*conn)->next = firstusedconn;
  }
  else { /* First insert */
    lastusedconn = *conn;
  }
  
  firstusedconn = *conn;
  
  (*conn)->inuse = 1;
  (*conn)->unit = n;
  
  return 0; /* Success */
}

int static freeconn(struct app_conn_t *conn) {
  int n = conn->unit;

  /* Remove from link of used */
  if ((conn->next) && (conn->prev)) {
    conn->next->prev = conn->prev;
    conn->prev->next = conn->next;
  }
  else if (conn->next) { /* && prev == 0 */
    conn->next->prev = NULL;
    firstusedconn = conn->next;
  }
  else if (conn->prev) { /* && next == 0 */
    conn->prev->next = NULL;
    lastusedconn = conn->prev;
  }
  else { /* if ((next == 0) && (prev == 0)) */
    firstusedconn = NULL;
    lastusedconn = NULL;
  }
  
  /* Initialise structures */
  memset(conn, 0, sizeof(struct app_conn_t));
  conn->unit = n;
  
  /* Insert into link of free */
  if (firstfreeconn) {
    firstfreeconn->prev = conn;
  }
  else { /* First insert */
    lastfreeconn = conn;
  }

  conn->next = firstfreeconn;
  firstfreeconn = conn;

  return 0;
}

int static getconn(struct app_conn_t **conn, uint32_t nasip, uint32_t nasport) {
  struct app_conn_t *appconn;
  
  /* Count the number of used connections */
  appconn = firstusedconn;
  while (appconn) {
    if (!appconn->inuse) {
      log_err(0, "Connection with inuse == 0!");
    }
    if ((appconn->nasip == nasip) && (appconn->nasport == nasport)) {
      *conn = appconn;
      return 0;
    }
    appconn = appconn->next;
  }

  return -1; /* Not found */
}

int static dnprot_terminate(struct app_conn_t *appconn) {
  appconn->s_state.authenticated = 0;
  printstatus(appconn);
  switch (appconn->dnprot) {
  case DNPROT_WPA:
  case DNPROT_EAPOL:
    if (!appconn->dnlink) {
      log_err(0, "No downlink protocol");
      return 0;
    }
    ((struct dhcp_conn_t*) appconn->dnlink)->authstate = DHCP_AUTH_NONE;
    return 0;
  case DNPROT_MAC:
  case DNPROT_UAM:
    if (!appconn->dnlink) {
      log_err(0, "No downlink protocol");
      return 0;
    }
    ((struct dhcp_conn_t*) appconn->dnlink)->authstate = DHCP_AUTH_DNAT;
    return 0;
  case DNPROT_DHCP_NONE:
  case DNPROT_NULL:
    return 0;
  default: 
    log_err(0, "Unknown downlink protocol"); 
    return 0;
  }
}



/* Check for:
 * - Session-Timeout
 * - Idle-Timeout
 * - Interim-Interim accounting
 * - Reread configuration file and DNS entries
 */

void session_interval(struct app_conn_t *conn) {
  time_t timenow = mainclock;
  uint32_t sessiontime;
  uint32_t idletime;
  uint32_t interimtime;

  sessiontime = timenow - conn->s_state.start_time;
  idletime    = timenow - conn->s_state.last_time;
  interimtime = timenow - conn->s_state.interim_time;
  
  if ((conn->s_params.sessiontimeout) &&
      (sessiontime > conn->s_params.sessiontimeout)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->s_params.sessionterminatetime) && 
	   (timenow > conn->s_params.sessionterminatetime)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->s_params.idletimeout) && 
	   (idletime > conn->s_params.idletimeout)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_IDLE_TIMEOUT);
  }
  else if ((conn->s_params.maxinputoctets) &&
	   (conn->s_state.input_octets > conn->s_params.maxinputoctets)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->s_params.maxoutputoctets) &&
	   (conn->s_state.output_octets > conn->s_params.maxoutputoctets)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->s_params.maxtotaloctets) &&
	   ((conn->s_state.input_octets + conn->s_state.output_octets) > 
	    conn->s_params.maxtotaloctets)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->s_params.interim_interval) &&
	   (interimtime > conn->s_params.interim_interval)) {
    acct_req(conn, RADIUS_STATUS_TYPE_INTERIM_UPDATE);
  }
}

int static checkconn()
{
  time_t timenow = mainclock;
  struct app_conn_t *conn;
  struct dhcp_conn_t* dhcpconn;
  uint32_t checkdiff;
  uint32_t rereaddiff;

  checkdiff = timenow - checktime;

  if (checkdiff < CHECK_INTERVAL)
    return 0;

  checktime = timenow;
  
  if (admin_session.s_state.authenticated) {
    session_interval(&admin_session);
  }

  for (conn = firstusedconn; conn; conn=conn->next) {
    if ((conn->inuse != 0) && (conn->s_state.authenticated == 1)) {
      if (!(dhcpconn = (struct dhcp_conn_t *)conn->dnlink)) {
	log_err(0, "No downlink protocol");
	return -1;
      }
      session_interval(conn);
    }
  }
  
  /* Reread configuration file and recheck DNS */
  if (options.interval) {
    rereaddiff = timenow - rereadtime;
    if (rereaddiff >= options.interval) {
      rereadtime = timenow;
      do_sighup = 1;
    }
  }
  
  return 0;
}

/* Kill all connections and send Radius Acct Stop */
int static killconn()
{
  struct app_conn_t *conn;
  struct dhcp_conn_t* dhcpconn;

  for (conn = firstusedconn; conn; conn=conn->next) {
    if ((conn->inuse != 0) && (conn->s_state.authenticated == 1)) {
      if (!(dhcpconn = (struct dhcp_conn_t *)conn->dnlink)) {
	log_err(0, "No downlink protocol");
	return -1;
      }
      terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_NAS_REBOOT);
    }
  }

  if (admin_session.s_state.authenticated) {
    admin_session.s_state.terminate_cause = RADIUS_TERMINATE_CAUSE_NAS_REBOOT;
    acct_req(&admin_session, RADIUS_STATUS_TYPE_STOP);
  }

  acct_req(&admin_session, RADIUS_STATUS_TYPE_ACCOUNTING_OFF);

  return 0;
}

/* Compare a MAC address to the addresses given in the macallowed option */
int static maccmp(unsigned char *mac) {
  int i;
  for (i=0; i<options.macoklen; i++) {
    if (!memcmp(mac, options.macok[i], PKT_ETH_ALEN)) {
      return 0;
    }
  }
  return -1;
}

int static macauth_radius(struct app_conn_t *appconn, 
			  struct dhcp_fullpacket_t *dhcp_pkt, size_t dhcp_len) {
  struct dhcp_conn_t *dhcpconn = (struct dhcp_conn_t *)appconn->dnlink;
  struct radius_packet_t radius_pack;
  char mac[MACSTRLEN+1];

  log_dbg("Starting mac radius authentication");

  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REQUEST)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }
  
  /* Include his MAC address */
  snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	   dhcpconn->hismac[0], dhcpconn->hismac[1],
	   dhcpconn->hismac[2], dhcpconn->hismac[3],
	   dhcpconn->hismac[4], dhcpconn->hismac[5]);

  strncpy(appconn->s_state.redir.username, mac, USERNAMESIZE);

  if (options.macsuffix)
    strncat(appconn->s_state.redir.username, options.macsuffix, USERNAMESIZE);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
		 (uint8_t*) appconn->s_state.redir.username, 
		 strlen(appconn->s_state.redir.username));
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
		 (uint8_t*) (options.macpasswd ? options.macpasswd : appconn->s_state.redir.username), 
		 options.macpasswd ? strlen(options.macpasswd) : strlen(appconn->s_state.redir.username));
  
  appconn->authtype = PAP_PASSWORD;
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0,
		 (uint8_t*) mac, MACSTRLEN);
  
  radius_addcalledstation(radius, &radius_pack);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		 appconn->unit, NULL, 0);

  radius_addnasip(radius, &radius_pack);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_SERVICE_TYPE, 0, 0,
		 RADIUS_SERVICE_TYPE_LOGIN, NULL, 0); /* WISPr_V1.0 */
  
  /* Include NAS-Identifier if given in configuration options */
  if (options.radiusnasid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
		   (uint8_t*) options.radiusnasid, strlen(options.radiusnasid));

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0,
		 (uint8_t*) appconn->s_state.sessionid, REDIR_SESSIONID_LEN-1);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		 options.radiusnasporttype, NULL, 0);


  if (options.radiuslocationid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_ID, 0,
		   (uint8_t*) options.radiuslocationid, 
		   strlen(options.radiuslocationid));

  if (options.radiuslocationname)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_NAME, 0,
		   (uint8_t*) options.radiuslocationname, 
		   strlen(options.radiuslocationname));

  if (options.dhcpradius && dhcp_pkt) {
    struct dhcp_tag_t *tag = 0;

#define maptag(OPT,VSA)\
    if (!dhcp_gettag(&dhcp_pkt->dhcp, ntohs(dhcp_pkt->udph.len)-PKT_UDP_HLEN, &tag, OPT)) { \
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC, \
		     RADIUS_VENDOR_CHILLISPOT, VSA, 0, (uint8_t *) tag->v, tag->l); } 

    maptag(DHCP_OPTION_PARAMETER_REQUEST_LIST, RADIUS_ATTR_CHILLISPOT_DHCP_PARAMETER_REQUEST_LIST);
    maptag(DHCP_OPTION_VENDOR_CLASS_IDENTIFIER, RADIUS_ATTR_CHILLISPOT_DHCP_VENDOR_CLASS_ID);
    maptag(DHCP_OPTION_CLIENT_IDENTIFIER, RADIUS_ATTR_CHILLISPOT_DHCP_CLIENT_ID);
    maptag(DHCP_OPTION_CLIENT_FQDN, RADIUS_ATTR_CHILLISPOT_DHCP_CLIENT_FQDN);
    maptag(DHCP_OPTION_HOSTNAME, RADIUS_ATTR_CHILLISPOT_DHCP_HOSTNAME);
  }
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		 0, 0, 0, NULL, RADIUS_MD5LEN);

  return radius_req(radius, &radius_pack, appconn);
}


/*********************************************************
 *
 * radius proxy functions
 * Used to send a response to a received radius request
 *
 *********************************************************/

/* Reply with an access reject */
int static radius_access_reject(struct app_conn_t *conn) {
  struct radius_packet_t radius_pack;

  conn->radiuswait = 0;

  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REJECT)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }

  radius_pack.id = conn->radiusid;
  radius_resp(radius, &radius_pack, &conn->radiuspeer, conn->authenticator);
  return 0;
}

/* Reply with an access challenge */
int static radius_access_challenge(struct app_conn_t *conn) {
  struct radius_packet_t radius_pack;
  size_t offset = 0;
  size_t eaplen = 0;

  conn->radiuswait = 0;

  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_CHALLENGE)){
    log_err(0, "radius_default_pack() failed");
    return -1;
  }

  radius_pack.id = conn->radiusid;

  /* Include EAP */
  do {
    if ((conn->challen - offset) > RADIUS_ATTR_VLEN)
      eaplen = RADIUS_ATTR_VLEN;
    else
      eaplen = conn->challen - offset;

    if (radius_addattr(radius, &radius_pack, RADIUS_ATTR_EAP_MESSAGE, 0, 0, 0,
		       conn->chal + offset, eaplen)) {
      log_err(0, "radius_default_pack() failed");
      return -1;
    }
    offset += eaplen;
  } while (offset < conn->challen);
  
  if (conn->s_state.redir.statelen) {
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_STATE, 0, 0, 0,
		   conn->s_state.redir.statebuf,
		   conn->s_state.redir.statelen);
  }
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		 0, 0, 0, NULL, RADIUS_MD5LEN);
  
  radius_resp(radius, &radius_pack, &conn->radiuspeer, conn->authenticator);
  return 0;
}

/* Send off an access accept */

int static radius_access_accept(struct app_conn_t *conn) {
  struct radius_packet_t radius_pack;
  size_t offset = 0;
  size_t eaplen = 0;

  uint8_t mppekey[RADIUS_ATTR_VLEN];
  size_t mppelen;

  conn->radiuswait = 0;

  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_ACCEPT)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }

  radius_pack.id = conn->radiusid;

  /* Include EAP (if present) */
  offset = 0;
  while (offset < conn->challen) {
    if ((conn->challen - offset) > RADIUS_ATTR_VLEN)
      eaplen = RADIUS_ATTR_VLEN;
    else
      eaplen = conn->challen - offset;

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_EAP_MESSAGE, 0, 0, 0,
		   conn->chal + offset, eaplen);

    offset += eaplen;
  }

  if (conn->sendlen) {
    radius_keyencode(radius, mppekey, RADIUS_ATTR_VLEN,
		     &mppelen, conn->sendkey,
		     conn->sendlen, conn->authenticator,
		     radius->proxysecret, radius->proxysecretlen);

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_MS, RADIUS_ATTR_MS_MPPE_SEND_KEY, 0,
		   (uint8_t *)mppekey, mppelen);
  }

  if (conn->recvlen) {
    radius_keyencode(radius, mppekey, RADIUS_ATTR_VLEN,
		     &mppelen, conn->recvkey,
		     conn->recvlen, conn->authenticator,
		     radius->proxysecret, radius->proxysecretlen);
    
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_MS, RADIUS_ATTR_MS_MPPE_RECV_KEY, 0,
		   (uint8_t *)mppekey, mppelen);
  }
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		 0, 0, 0, NULL, RADIUS_MD5LEN);

  radius_resp(radius, &radius_pack, &conn->radiuspeer, conn->authenticator);
  return 0;
}


/*********************************************************
 *
 * radius accounting functions
 * Used to send accounting request to radius server
 *
 *********************************************************/

static int acct_req(struct app_conn_t *conn, uint8_t status_type)
{
  struct radius_packet_t radius_pack;
  char mac[MACSTRLEN+1];
  char portid[16+1];
  time_t timenow;
  uint32_t timediff;

  if (RADIUS_STATUS_TYPE_START == status_type) {
    conn->s_state.start_time = mainclock;
    conn->s_state.interim_time = mainclock;
    conn->s_state.last_time = mainclock;
    conn->s_state.input_packets = 0;
    conn->s_state.output_packets = 0;
    conn->s_state.input_octets = 0;
    conn->s_state.output_octets = 0;
  }

  if (RADIUS_STATUS_TYPE_INTERIM_UPDATE == status_type) {
    conn->s_state.interim_time = mainclock;
  }

  if (radius_default_pack(radius, &radius_pack, 
			  RADIUS_CODE_ACCOUNTING_REQUEST)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_STATUS_TYPE, 0, 0,
		 status_type, NULL, 0);

  if (RADIUS_STATUS_TYPE_ACCOUNTING_ON != status_type &&
      RADIUS_STATUS_TYPE_ACCOUNTING_OFF != status_type) {

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
		   (uint8_t*) conn->s_state.redir.username, 
		   strlen(conn->s_state.redir.username));
    
    if (conn->s_state.redir.classlen) {
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_CLASS, 0, 0, 0,
		     conn->s_state.redir.classbuf,
		     conn->s_state.redir.classlen);
    }

    if (conn->is_adminsession) {
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_SERVICE_TYPE, 0, 0,
		     RADIUS_SERVICE_TYPE_ADMIN_USER, NULL, 0); 
    } else {
      snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	       conn->hismac[0], conn->hismac[1],
	       conn->hismac[2], conn->hismac[3],
	       conn->hismac[4], conn->hismac[5]);
      
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0,
		     (uint8_t*) mac, MACSTRLEN);
      
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		     options.radiusnasporttype, NULL, 0);
      
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		     conn->unit, NULL, 0);

      snprintf(portid, 16+1, "%.8d", conn->unit);
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_ID, 0, 0, 0,
		     (uint8_t*) portid, strlen(portid));

      radius_addattr(radius, &radius_pack, RADIUS_ATTR_FRAMED_IP_ADDRESS, 0, 0,
		     ntohl(conn->hisip.s_addr), NULL, 0);
      
    }
    
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0,
		   (uint8_t*) conn->s_state.sessionid, REDIR_SESSIONID_LEN-1);
    
  }

  radius_addnasip(radius, &radius_pack);

  radius_addcalledstation(radius, &radius_pack);


  /* Include NAS-Identifier if given in configuration options */
  if (options.radiusnasid)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
		   (uint8_t*) options.radiusnasid, 
		   strlen(options.radiusnasid));

  /*
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_FRAMED_MTU, 0, 0,
  conn->mtu, NULL, 0);*/

  if ((status_type == RADIUS_STATUS_TYPE_STOP) ||
      (status_type == RADIUS_STATUS_TYPE_INTERIM_UPDATE)) {

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_INPUT_OCTETS, 0, 0,
		   (uint32_t) conn->s_state.input_octets, NULL, 0);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_OUTPUT_OCTETS, 0, 0,
		   (uint32_t) conn->s_state.output_octets, NULL, 0);

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_INPUT_GIGAWORDS, 
		   0, 0, (uint32_t) (conn->s_state.input_octets >> 32), NULL, 0);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS, 
		   0, 0, (uint32_t) (conn->s_state.output_octets >> 32), NULL, 0);

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_INPUT_PACKETS, 0, 0,
		   conn->s_state.input_packets, NULL, 0);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_OUTPUT_PACKETS, 0, 0,
		   conn->s_state.output_packets, NULL, 0);

    timenow = mainclock;
    timediff = timenow - conn->s_state.start_time;

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_SESSION_TIME, 0, 0,
		   timediff, NULL, 0);  
  }

  if (options.radiuslocationid)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_ID, 0,
		   (uint8_t*) options.radiuslocationid,
		   strlen(options.radiuslocationid));

  if (options.radiuslocationname)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_NAME, 0,
		   (uint8_t*) options.radiuslocationname, 
		   strlen(options.radiuslocationname));


  if (status_type == RADIUS_STATUS_TYPE_STOP ||
      status_type == RADIUS_STATUS_TYPE_ACCOUNTING_OFF) {

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_TERMINATE_CAUSE, 
		   0, 0, conn->s_state.terminate_cause, NULL, 0);

    if (status_type == RADIUS_STATUS_TYPE_STOP) {
      /* TODO: This probably belongs somewhere else */
      if (options.condown) {
	if (options.debug)
	  log_dbg("Calling connection down script: %s\n",options.condown);
	runscript(conn, options.condown);
      }
    }
  }
  
  radius_req(radius, &radius_pack, conn);
  
  return 0;
}



/***********************************************************
 *
 * Functions handling downlink protocol authentication.
 * Called in response to radius access request response.
 *
 ***********************************************************/

int static dnprot_reject(struct app_conn_t *appconn) {
  struct dhcp_conn_t* dhcpconn = NULL;
  /*struct ippoolm_t *ipm;*/

  switch (appconn->dnprot) {

  case DNPROT_EAPOL:
    if (!(dhcpconn = (struct dhcp_conn_t*) appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    dhcp_sendEAPreject(dhcpconn, NULL, 0);
    return 0;

  case DNPROT_UAM:
    log_err(0, "Rejecting UAM");
    return 0;

  case DNPROT_WPA:
    return radius_access_reject(appconn);

  case DNPROT_MAC:
    /* remove the username since we're not logged in */
    if (!appconn->s_state.authenticated)
      strncpy(appconn->s_state.redir.username, "-", USERNAMESIZE);

    if (!(dhcpconn = (struct dhcp_conn_t *)appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    if (options.macauthdeny) {
      dhcpconn->authstate = DHCP_AUTH_DROP;
      appconn->dnprot = DNPROT_NULL;
    }
    else {
      dhcpconn->authstate = DHCP_AUTH_NONE;
      appconn->dnprot = DNPROT_UAM;
    }

    return 0;    

  case DNPROT_NULL:
    return 0;

  default:
    log_err(0, "Unknown downlink protocol");
    return 0;
  }
}

int static dnprot_challenge(struct app_conn_t *appconn) {
  struct dhcp_conn_t* dhcpconn = NULL;

  switch (appconn->dnprot) {

  case DNPROT_EAPOL:
    if (!(dhcpconn = (struct dhcp_conn_t *)appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    dhcp_sendEAP(dhcpconn, appconn->chal, appconn->challen);
    break;

  case DNPROT_NULL:
  case DNPROT_UAM:
  case DNPROT_MAC:
    break;

  case DNPROT_WPA:
    radius_access_challenge(appconn);
    break;

  default:
    log_err(0, "Unknown downlink protocol");
  }

  return 0;
}

int static dnprot_accept(struct app_conn_t *appconn) {
  struct dhcp_conn_t* dhcpconn = NULL;
  
  if (appconn->is_adminsession) return 0;

  if (!appconn->hisip.s_addr) {
    log_err(0, "IP address not allocated");
    return 0;
  }

  switch (appconn->dnprot) {
  case DNPROT_EAPOL:
    if (!(dhcpconn = (struct dhcp_conn_t *)appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    dhcp_set_addrs(dhcpconn, 
		   &appconn->hisip, &appconn->mask,
		   &appconn->ourip, &appconn->mask,
		   &appconn->dns1, &appconn->dns2,
		   options.domain);
    
    /* This is the one and only place eapol authentication is accepted */

    dhcpconn->authstate = DHCP_AUTH_PASS;

    /* Tell client it was successful */
    dhcp_sendEAP(dhcpconn, appconn->chal, appconn->challen);

    log_warn(0, "Do not know how to set encryption keys on this platform!");
    break;

  case DNPROT_UAM:
    if (!(dhcpconn = (struct dhcp_conn_t *)appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    dhcp_set_addrs(dhcpconn, 
		   &appconn->hisip, &appconn->mask,
		   &appconn->ourip, &appconn->mask,
		   &appconn->dns1, &appconn->dns2,
		   options.domain);

    /* This is the one and only place UAM authentication is accepted */
    dhcpconn->authstate = DHCP_AUTH_PASS;
    appconn->s_params.flags &= ~REQUIRE_UAM_AUTH;
    break;

  case DNPROT_WPA:
    if (!(dhcpconn = (struct dhcp_conn_t *)appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    dhcp_set_addrs(dhcpconn, 
		   &appconn->hisip, &appconn->mask, 
		   &appconn->ourip, &appconn->mask, 
		   &appconn->dns1, &appconn->dns2,
		   options.domain);
    
    /* This is the one and only place WPA authentication is accepted */
    if (appconn->s_params.flags & REQUIRE_UAM_AUTH) {
      appconn->dnprot = DNPROT_DHCP_NONE;
      dhcpconn->authstate = DHCP_AUTH_NONE;
    }
    else {
      dhcpconn->authstate = DHCP_AUTH_PASS;
    }
    
    /* Tell access point it was successful */
    radius_access_accept(appconn);

    break;

  case DNPROT_MAC:
    if (!(dhcpconn = (struct dhcp_conn_t *)appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    dhcp_set_addrs(dhcpconn, 
		   &appconn->hisip, &appconn->mask, 
		   &appconn->ourip, &appconn->mask, 
		   &appconn->dns1, &appconn->dns2,
		   options.domain);
    
    dhcpconn->authstate = DHCP_AUTH_PASS;
    break;

  case DNPROT_NULL:
  case DNPROT_DHCP_NONE:
    return 0;

  default:
    log_err(0, "Unknown downlink protocol");
    return 0;
  }

  if (appconn->s_params.flags & REQUIRE_UAM_SPLASH)
    dhcpconn->authstate = DHCP_AUTH_SPLASH;
  
  if (!(appconn->s_params.flags & REQUIRE_UAM_AUTH)) {
    /* This is the one and only place state is switched to authenticated */
    appconn->s_state.authenticated = 1;
    
    /* Run connection up script */
    if (options.conup) {
      if (options.debug) log_dbg("Calling connection up script: %s\n", options.conup);
      runscript(appconn, options.conup);
    }
    
    printstatus(appconn);
    
    if (!(appconn->s_params.flags & IS_UAM_REAUTH))
      acct_req(appconn, RADIUS_STATUS_TYPE_START);
  }
  
  appconn->s_params.flags &= ~IS_UAM_REAUTH;
  return 0;
}


/*
 * Tun callbacks
 *
 * Called from the tun_decaps function. This method is passed either
 * a Ethernet frame or an IP packet. 
 */

int cb_tun_ind(struct tun_t *tun, void *pack, size_t len, int idx) {
  struct in_addr dst;
  struct ippoolm_t *ipm;
  struct app_conn_t *appconn;
  struct pkt_ipphdr_t *ipph;

  int ethhdr = !!(tun(tun, idx).flags & NET_ETHHDR);

  if (ethhdr) {
    struct pkt_ethhdr_t *ethh = (struct pkt_ethhdr_t *)pack;
    uint16_t prot = ntohs(ethh->prot);

    ipph = (struct pkt_ipphdr_t *)((char *)pack + PKT_ETH_HLEN);

    if (prot == PKT_ETH_PROTO_ARP) {
      /*
       * send arp reply with us being target
       */
      struct arp_fullpacket_t *p = (struct arp_fullpacket_t *)pack;
      struct arp_fullpacket_t packet;
      struct in_addr reqaddr;
      size_t length = sizeof(packet);
      
      log_dbg("arp: dst=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x src=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x prot=%.4x\n",
	      ethh->dst[0],ethh->dst[1],ethh->dst[2],ethh->dst[3],ethh->dst[4],ethh->dst[5],
	      ethh->src[0],ethh->src[1],ethh->src[2],ethh->src[3],ethh->src[4],ethh->src[5],
	      ntohs(ethh->prot));
      
      /* Get local copy */
      memcpy(&reqaddr.s_addr, p->arp.tpa, PKT_IP_ALEN);
      
      if (ippool_getip(ippool, &ipm, &reqaddr)) {
	if (options.debug) 
	    log_dbg("ARP for unknown IP %s\n", inet_ntoa(reqaddr));
	return 0;
      }
      
      if ((appconn  = (struct app_conn_t *)ipm->peer) == NULL ||
	  (appconn->dnlink) == NULL) {
	log_err(0, "No peer protocol defined for ARP request");
	return 0;
      }
      
      /* Get packet default values */
      memset(&packet, 0, sizeof(packet));
      
      /* ARP Payload */
      packet.arp.hrd = htons(DHCP_HTYPE_ETH);
      packet.arp.pro = htons(PKT_ETH_PROTO_IP);
      packet.arp.hln = PKT_ETH_ALEN;
      packet.arp.pln = PKT_IP_ALEN;
      packet.arp.op  = htons(DHCP_ARP_REPLY);
      
      /* Source address */
      /*memcpy(packet.arp.sha, dhcp->arp_hwaddr, PKT_ETH_ALEN);
	memcpy(packet.arp.spa, &dhcp->ourip.s_addr, PKT_IP_ALEN);*/
      /*memcpy(packet.arp.sha, appconn->hismac, PKT_ETH_ALEN);*/
      memcpy(packet.arp.sha, tun->_interfaces[0].hwaddr, PKT_ETH_ALEN);
      memcpy(packet.arp.spa, &appconn->hisip.s_addr, PKT_IP_ALEN);
	
      /* Target address */
      /*memcpy(packet.arp.tha, &appconn->hismac, PKT_ETH_ALEN);
	memcpy(packet.arp.tpa, &appconn->hisip.s_addr, PKT_IP_ALEN); */
      memcpy(packet.arp.tha, p->arp.sha, PKT_ETH_ALEN);
      memcpy(packet.arp.tpa, p->arp.spa, PKT_IP_ALEN);
      
      /* Ethernet header */
      memcpy(packet.ethh.dst, p->ethh.src, PKT_ETH_ALEN);
      memcpy(packet.ethh.src, dhcp->ipif.hwaddr, PKT_ETH_ALEN);
      packet.ethh.prot = htons(PKT_ETH_PROTO_ARP);
      
      return tun_encaps(tun, &packet, length, idx);
    }
  } else {
    ipph = (struct pkt_ipphdr_t *)pack;
  }

  /*if (options.debug) 
    log_dbg("cb_tun_ind. Packet received: Forwarding to link layer");*/

  dst.s_addr = ipph->daddr;

  if (ippool_getip(ippool, &ipm, &dst)) {
    if (options.debug) 
      log_dbg("dropping packet with unknown destination: %s", inet_ntoa(dst));
    return 0;
  }
  
  if ((appconn = (struct app_conn_t *)ipm->peer) == NULL ||
      (appconn->dnlink) == NULL) {
    log_err(0, "No peer protocol defined");
    return 0;
  }
  
  /* If the ip src is uamlisten and psrc is uamport we won't call leaky_bucket */
  if ( ! (ipph->saddr  == options.uamlisten.s_addr && 
	  (ipph->sport == htons(options.uamport) ||
	   ipph->sport == htons(options.uamuiport)))) {
    if (appconn->s_state.authenticated == 1) {

#ifndef LEAKY_BUCKET
      appconn->s_state.last_time = mainclock;
#endif

#ifdef LEAKY_BUCKET
#ifndef COUNT_DOWNLINK_DROP
    if (leaky_bucket(appconn, 0, len)) return 0;
#endif
#endif
    if (options.swapoctets) {
      appconn->s_state.output_packets++;
      appconn->s_state.output_octets += len;
      if (admin_session.s_state.authenticated) {
	admin_session.s_state.output_packets++;
	admin_session.s_state.output_octets+=len;
      }
    } else {
      appconn->s_state.input_packets++;
      appconn->s_state.input_octets += len;
      if (admin_session.s_state.authenticated) {
	admin_session.s_state.input_packets++;
	admin_session.s_state.input_octets+=len;
      }
    }
#ifdef LEAKY_BUCKET
#ifdef COUNT_DOWNLINK_DROP
    if (leaky_bucket(appconn, 0, len)) return 0;
#endif
#endif
    }
  }

  switch (appconn->dnprot) {
  case DNPROT_NULL:
  case DNPROT_DHCP_NONE:
    break;

  case DNPROT_UAM:
  case DNPROT_WPA:
  case DNPROT_MAC:
  case DNPROT_EAPOL:
    dhcp_data_req((struct dhcp_conn_t *)appconn->dnlink, pack, len, ethhdr);
    break;

  default:
    log_err(0, "Unknown downlink protocol: %d", appconn->dnprot);
    break;
  }

  return 0;
}


/*********************************************************
 *
 * Redir callbacks
 *
 *********************************************************/

int cb_redir_getstate(struct redir_t *redir, struct in_addr *addr,
		      struct redir_conn_t *conn) {
  struct ippoolm_t *ipm;
  struct app_conn_t *appconn;
  struct dhcp_conn_t *dhcpconn;

  if (ippool_getip(ippool, &ipm, addr)) {
    return -1;
  }
  
  if ( (appconn  = (struct app_conn_t *)ipm->peer)        == NULL || 
       (dhcpconn = (struct dhcp_conn_t *)appconn->dnlink) == NULL ) {
    log_warn(0, "No peer protocol defined");
    return -1;
  }
  
  conn->nasip = options.radiuslisten;
  conn->nasport = appconn->unit;
  memcpy(conn->hismac, dhcpconn->hismac, PKT_ETH_ALEN);
  memcpy(conn->ourmac, dhcpconn->ourmac, PKT_ETH_ALEN);
  conn->ourip = appconn->ourip;
  conn->hisip = appconn->hisip;

  memcpy(&conn->s_params, &appconn->s_params, sizeof(appconn->s_params));
  memcpy(&conn->s_state,  &appconn->s_state,  sizeof(appconn->s_state));

  /* reset state */
  appconn->uamexit=0;
  return conn->s_state.authenticated == 1;
}


/*********************************************************
 *
 * Functions supporting radius callbacks
 *
 *********************************************************/

/* Handle an accounting request */
int accounting_request(struct radius_packet_t *pack,
		       struct sockaddr_in *peer) {
  struct radius_attr_t *hismacattr = NULL;
  struct radius_attr_t *typeattr = NULL;
  struct radius_attr_t *nasipattr = NULL;
  struct radius_attr_t *nasportattr = NULL;
  struct radius_packet_t radius_pack;
  struct app_conn_t *appconn = NULL;
  struct dhcp_conn_t *dhcpconn = NULL;
  uint8_t hismac[PKT_ETH_ALEN];
  char macstr[RADIUS_ATTR_VLEN];
  size_t macstrlen;
  unsigned int temp[PKT_ETH_ALEN];
  uint32_t nasip = 0;
  uint32_t nasport = 0;
  int i;


  if (radius_default_pack(radius, &radius_pack, 
			  RADIUS_CODE_ACCOUNTING_RESPONSE)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }
  radius_pack.id = pack->id;
  
  /* Status type */
  if (radius_getattr(pack, &typeattr, RADIUS_ATTR_ACCT_STATUS_TYPE, 0, 0, 0)) {
    log_err(0, "Status type is missing from radius request");
    radius_resp(radius, &radius_pack, peer, pack->authenticator);
    return 0;
  }

  if (typeattr->v.i != htonl(RADIUS_STATUS_TYPE_STOP)) {
    radius_resp(radius, &radius_pack, peer, pack->authenticator);
    return 0;
  }


  /* NAS IP */
  if (!radius_getattr(pack, &nasipattr, RADIUS_ATTR_NAS_IP_ADDRESS, 0, 0, 0)) {
    if ((nasipattr->l-2) != sizeof(appconn->nasip)) {
      log_err(0, "Wrong length of NAS IP address");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    nasip = nasipattr->v.i;
  }
  
  /* NAS PORT */
  if (!radius_getattr(pack, &nasportattr, RADIUS_ATTR_NAS_PORT, 0, 0, 0)) {
    if ((nasportattr->l-2) != sizeof(appconn->nasport)) {
      log_err(0, "Wrong length of NAS port");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    nasport = nasportattr->v.i;
  }
  
  /* Calling Station ID (MAC Address) */
  if (!radius_getattr(pack, &hismacattr, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0)) {
    if (options.debug) {
      log_dbg("Calling Station ID is: %.*s", hismacattr->l-2, hismacattr->v.t);
    }
    if ((macstrlen = (size_t)hismacattr->l-2) >= (RADIUS_ATTR_VLEN-1)) {
      log_err(0, "Wrong length of called station ID");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    memcpy(macstr, hismacattr->v.t, macstrlen);
    macstr[macstrlen] = 0;
    
    /* Replace anything but hex with space */
    for (i=0; i<macstrlen; i++) 
      if (!isxdigit(macstr[i])) macstr[i] = 0x20;
    
    if (sscanf (macstr, "%2x %2x %2x %2x %2x %2x",
		&temp[0], &temp[1], &temp[2], 
		&temp[3], &temp[4], &temp[5]) != 6) {
      log_err(0,
	      "Failed to convert Calling Station ID to MAC Address");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    
    for(i = 0; i < PKT_ETH_ALEN; i++) 
      hismac[i] = temp[i];
  }

  if (hismacattr) { /* Look for mac address.*/
    if (dhcp_hashget(dhcp, &dhcpconn, hismac)) {
      log_err(0, "Unknown connection");
      radius_resp(radius, &radius_pack, peer, pack->authenticator);
      return 0;
    }
    if (!(dhcpconn->peer) || !((struct app_conn_t *)dhcpconn->peer)->uplink) {
      log_err(0,"No peer protocol defined");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    appconn = (struct app_conn_t*) dhcpconn->peer;
  }
  else if (nasipattr && nasportattr) { /* Look for NAS IP / Port */
    if (getconn(&appconn, nasip, nasport)) {
      log_err(0, "Unknown connection");
      radius_resp(radius, &radius_pack, peer, pack->authenticator);
      return 0;
    }
  }
  else {
    log_err(0,
	    "Calling Station ID or NAS IP/Port is missing from radius request");
    radius_resp(radius, &radius_pack, peer, pack->authenticator);
    return 0;
  }
  
  /* Silently ignore radius request if allready processing one */
  if (appconn->radiuswait) {
    if (appconn->radiuswait == 2) {
      log_dbg("Giving up on previous packet.. not dropping this one");
      appconn->radiuswait=0;
    } else {
      log_dbg("Dropping RADIUS while waiting");
      appconn->radiuswait++;
      return 0;
    }
  }
  
  /* TODO: Check validity of pointers */
  
  switch (appconn->dnprot) {
  case DNPROT_UAM:
    log_err(0,"Auth stop received for UAM");
    break;
  case DNPROT_WPA:
    dhcpconn = (struct dhcp_conn_t*) appconn->dnlink;
    if (!dhcpconn) {
      log_err(0,"No downlink protocol");
      return 0;
    }
    /* Connection is simply deleted */
    dhcp_freeconn(dhcpconn, RADIUS_TERMINATE_CAUSE_LOST_CARRIER);
    break;
  default:
    log_err(0,"Unhandled downlink protocol %d", appconn->dnprot);
    radius_resp(radius, &radius_pack, peer, pack->authenticator);
    return 0;
  }

  radius_resp(radius, &radius_pack, peer, pack->authenticator);

  return 0;
}


int access_request(struct radius_packet_t *pack,
		   struct sockaddr_in *peer) {
  int n;
  struct radius_packet_t radius_pack;

  struct ippoolm_t *ipm = NULL;

  struct radius_attr_t *hisipattr = NULL;
  struct radius_attr_t *nasipattr = NULL;
  struct radius_attr_t *nasportattr = NULL;
  struct radius_attr_t *hismacattr = NULL;
  struct radius_attr_t *uidattr = NULL;
  struct radius_attr_t *pwdattr = NULL;
  struct radius_attr_t *eapattr = NULL;

  struct in_addr hisip;
  char pwd[RADIUS_ATTR_VLEN];
  size_t pwdlen;
  uint8_t hismac[PKT_ETH_ALEN];
  char macstr[RADIUS_ATTR_VLEN];
  size_t macstrlen;
  unsigned int temp[PKT_ETH_ALEN];
  char mac[MACSTRLEN+1];
  int i;

  struct app_conn_t *appconn = NULL;
  struct dhcp_conn_t *dhcpconn = NULL;

  uint8_t resp[EAP_LEN];         /* EAP response */
  size_t resplen;                /* Length of EAP response */

  size_t offset = 0;
  size_t eaplen = 0;
  int instance = 0;

  if (options.debug) 
    log_dbg("RADIUS Access-Request received");

  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REJECT)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }

  radius_pack.id = pack->id;

  /* User is identified by either IP address OR MAC address */
  
  /* Framed IP address (Conditional) */
  if (!radius_getattr(pack, &hisipattr, RADIUS_ATTR_FRAMED_IP_ADDRESS, 0, 0, 0)) {
    if (options.debug) {
      log_dbg("Framed IP address is: ");
      for (n=0; n<hisipattr->l-2; n++) log_dbg("%.2x", hisipattr->v.t[n]); 
      log_dbg("\n");
    }
    if ((hisipattr->l-2) != sizeof(hisip.s_addr)) {
      log_err(0, "Wrong length of framed IP address");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    hisip.s_addr = hisipattr->v.i;
  }

  /* Calling Station ID: MAC Address (Conditional) */
  if (!radius_getattr(pack, &hismacattr, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0)) {
    if (options.debug) {
      log_dbg("Calling Station ID is: %.*s", hismacattr->l-2, hismacattr->v.t);
    }
    if ((macstrlen = (size_t)hismacattr->l-2) >= (RADIUS_ATTR_VLEN-1)) {
      log_err(0, "Wrong length of called station ID");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    memcpy(macstr, hismacattr->v.t, macstrlen);
    macstr[macstrlen] = 0;

    /* Replace anything but hex with space */
    for (i=0; i<macstrlen; i++) 
      if (!isxdigit(macstr[i])) macstr[i] = 0x20;

    if (sscanf (macstr, "%2x %2x %2x %2x %2x %2x",
		&temp[0], &temp[1], &temp[2], 
		&temp[3], &temp[4], &temp[5]) != 6) {
      log_err(0, "Failed to convert Calling Station ID to MAC Address");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    
    for(i = 0; i < PKT_ETH_ALEN; i++) 
      hismac[i] = temp[i];
  }

  /* Framed IP address or MAC Address must be given in request */
  if ((!hisipattr) && (!hismacattr)) {
    log_err(0, "Framed IP address or Calling Station ID is missing from radius request");
    return radius_resp(radius, &radius_pack, peer, pack->authenticator);
  }

  /* Username (Mandatory) */
  if (radius_getattr(pack, &uidattr, RADIUS_ATTR_USER_NAME, 0, 0, 0)) {
    log_err(0, "User-Name is missing from radius request");
    return radius_resp(radius, &radius_pack, peer, pack->authenticator);
  } 

  if (hisipattr) { /* Find user based on IP address */
    if (ippool_getip(ippool, &ipm, &hisip)) {
      log_err(0, "RADIUS-Request: IP Address not found");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    
    if ((appconn  = (struct app_conn_t *)ipm->peer)        == NULL || 
	(dhcpconn = (struct dhcp_conn_t *)appconn->dnlink) == NULL) {
      log_err(0, "RADIUS-Request: No peer protocol defined");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
  }
  else if (hismacattr) { /* Look for mac address. If not found allocate new */
    if (dhcp_hashget(dhcp, &dhcpconn, hismac)) {
      if (dhcp_newconn(dhcp, &dhcpconn, hismac)) {
	log_err(0, "Out of connections");
	return radius_resp(radius, &radius_pack, peer, pack->authenticator);
      }
    }
    if (!(dhcpconn->peer)) {
      log_err(0, "No peer protocol defined");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    appconn = (struct app_conn_t *)dhcpconn->peer;
    /*if (appconn->dnprot == DNPROT_DHCP_NONE)
    appconn->dnprot = DNPROT_WPA;*/
  }
  else {
    log_err(0, "Framed IP address or Calling Station ID is missing from radius request");
    return radius_resp(radius, &radius_pack, peer, pack->authenticator);
  }

  /* Silently ignore radius request if allready processing one */
  if (appconn->radiuswait) {
    if (appconn->radiuswait == 2) {
      log_dbg("Giving up on previous packet.. not dropping this one");
      appconn->radiuswait=0;
    } else {
      log_dbg("Dropping RADIUS while waiting");
      appconn->radiuswait++;
      return 0;
    }
  }
  
  /* Password */
  if (!radius_getattr(pack, &pwdattr, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0)) {
    if (radius_pwdecode(radius, (uint8_t*) pwd, RADIUS_ATTR_VLEN, &pwdlen, 
			pwdattr->v.t, pwdattr->l-2, pack->authenticator,
			radius->proxysecret,
			radius->proxysecretlen)) {
      log_err(0, "radius_pwdecode() failed");
      return -1;
    }
    if (options.debug) log_dbg("Password is: %s\n", pwd);
  }

  /* Get EAP message */
  resplen = 0;
  do {
    eapattr=NULL;
    if (!radius_getattr(pack, &eapattr, RADIUS_ATTR_EAP_MESSAGE, 0, 0, 
			instance++)) {
      if ((resplen + (size_t)eapattr->l-2) > EAP_LEN) {
	log(LOG_INFO, "EAP message too long");
	return radius_resp(radius, &radius_pack, peer, pack->authenticator);
      }
      memcpy(resp + resplen, eapattr->v.t, (size_t)eapattr->l-2);
      resplen += (size_t)eapattr->l-2;
    }
  } while (eapattr);
  

  /* Passwd or EAP must be given in request */
  if ((!pwdattr) && (!resplen)) {
    log_err(0, "Password or EAP meaasge is missing from radius request");
    return radius_resp(radius, &radius_pack, peer, pack->authenticator);
  }

  /* ChilliSpot Notes:
     Dublicate logins should be allowed as it might be the terminal
     moving from one access point to another. It is however
     unacceptable to login with another username on top of an allready
     existing connection 

     TODO: New username should be allowed, but should result in
     a accounting stop message for the old connection.
     this does however pose a denial of service attack possibility 
  
     If allready logged in send back accept message with username
     TODO ? Should this be a reject: Dont login twice ? 
  */

  /* Terminate previous session if trying to login with another username */
  if ((appconn->s_state.authenticated == 1) && 
      ((strlen(appconn->s_state.redir.username) != uidattr->l-2) ||
       (memcmp(appconn->s_state.redir.username, uidattr->v.t, uidattr->l-2)))) {
    terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_USER_REQUEST);
    /* DWB: But, let's not reject someone who is trying to authenticate under
       a new (potentially) valid account - that is for the up-stream RADIUS to discern
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);*/
  }

  /* Radius auth only for DHCP */
  /*if ((appconn->dnprot != DNPROT_UAM) && (appconn->dnprot != DNPROT_WPA))  { */
    /*return radius_resp(radius, &radius_pack, peer, pack->authenticator);*/
  appconn->dnprot = DNPROT_WPA;
  /*  }*/

  /* NAS IP */
  if (!radius_getattr(pack, &nasipattr, RADIUS_ATTR_NAS_IP_ADDRESS, 0, 0, 0)) {
    if ((nasipattr->l-2) != sizeof(appconn->nasip)) {
      log_err(0, "Wrong length of NAS IP address");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    appconn->nasip = nasipattr->v.i;
  }

  /* NAS PORT */
  if (!radius_getattr(pack, &nasportattr, RADIUS_ATTR_NAS_PORT, 0, 0, 0)) {
    if ((nasportattr->l-2) != sizeof(appconn->nasport)) {
      log_err(0, "Wrong length of NAS port");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    appconn->nasport = nasportattr->v.i;
  }

  /* Store parameters for later use */
  if (uidattr->l-2<=USERNAMESIZE) {
    strncpy(appconn->s_state.redir.username, 
	    (char *)uidattr->v.t, uidattr->l-2);
  }

  appconn->radiuswait = 1;
  appconn->radiusid = pack->id;

  if (pwdattr)
    appconn->authtype = PAP_PASSWORD;
  else
    appconn->authtype = EAP_MESSAGE;

  memcpy(&appconn->radiuspeer, peer, sizeof(*peer));
  memcpy(appconn->authenticator, pack->authenticator, RADIUS_AUTHLEN);
  memcpy(appconn->hismac, dhcpconn->hismac, PKT_ETH_ALEN);
  memcpy(appconn->ourmac, dhcpconn->ourmac, PKT_ETH_ALEN);

  /* Build up radius request */
  radius_pack.code = RADIUS_CODE_ACCESS_REQUEST;
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
		 uidattr->v.t, uidattr->l - 2);

  if (appconn->s_state.redir.statelen) {
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_STATE, 0, 0, 0,
		   appconn->s_state.redir.statebuf,
		   appconn->s_state.redir.statelen);
  }

  if (pwdattr)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
		   (uint8_t*) pwd, pwdlen);

  /* Include EAP (if present) */
  offset = 0;
  while (offset < resplen) {

    if ((resplen - offset) > RADIUS_ATTR_VLEN)
      eaplen = RADIUS_ATTR_VLEN;
    else
      eaplen = resplen - offset;

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_EAP_MESSAGE, 0, 0, 0,
		   resp + offset, eaplen);

    offset += eaplen;
  } 

  if (resplen) {
    if (options.wpaguests)
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		     RADIUS_VENDOR_CHILLISPOT, RADIUS_ATTR_CHILLISPOT_CONFIG, 
		     0, (uint8_t*)"allow-wpa-guests", 16);

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		   0, 0, 0, NULL, RADIUS_MD5LEN);
  }

  /* Include his MAC address */
  snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	   appconn->hismac[0], appconn->hismac[1],
	   appconn->hismac[2], appconn->hismac[3],
	   appconn->hismac[4], appconn->hismac[5]);
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0,
		 (uint8_t*) mac, MACSTRLEN);
  
  radius_addcalledstation(radius, &radius_pack);
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		 options.radiusnasporttype, NULL, 0);
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		 appconn->unit, NULL, 0);
  
  radius_addnasip(radius, &radius_pack);
  
  /* Include NAS-Identifier if given in configuration options */
  if (options.radiusnasid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
		   (uint8_t*) options.radiusnasid, strlen(options.radiusnasid));
  
  return radius_req(radius, &radius_pack, appconn);
}


/*********************************************************
 *
 * radius proxy callback functions (request from radius server)
 *
 *********************************************************/

/* Radius callback when radius request has been received */
int cb_radius_ind(struct radius_t *rp, struct radius_packet_t *pack,
		  struct sockaddr_in *peer) {

  if (rp != radius) {
    log_err(0, "Radius callback from unknown instance");
    return 0;
  }
  
  switch (pack->code) {
  case RADIUS_CODE_ACCOUNTING_REQUEST: /* TODO: Exclude ??? */
    return accounting_request(pack, peer);
  case RADIUS_CODE_ACCESS_REQUEST:
    return access_request(pack, peer);
  default:
    log_err(0, "Unsupported radius request received: %d", pack->code);
    return 0;
  }
}


int upprot_getip(struct app_conn_t *appconn, 
		 struct in_addr *hisip, int statip) {
  struct ippoolm_t *ipm;

  /* If IP address is allready allocated: Fill it in */
  /* This should only happen for UAM */
  /* TODO */
  if (appconn->uplink) {
    ipm = (struct ippoolm_t *)appconn->uplink;
  }
  else {
    /* Allocate static or dynamic IP address */

    if (newip(&ipm, hisip))
      return dnprot_reject(appconn);

    appconn->hisip.s_addr = ipm->addr.s_addr;

    /* TODO: Too many "listen" and "our" addresses having around */
    appconn->ourip.s_addr = options.dhcplisten.s_addr;
    
    appconn->uplink = ipm;
    ipm->peer = appconn; 
  }

  return dnprot_accept(appconn);

}

void config_radius_session(struct session_params *params, struct radius_packet_t *pack, int reconfig) {
  struct radius_attr_t *attr = NULL;

  /* Session timeout */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_SESSION_TIMEOUT, 0, 0, 0))
    params->sessiontimeout = ntohl(attr->v.i);
  else if (!reconfig)
    params->sessiontimeout = 0;

  /* Idle timeout */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_IDLE_TIMEOUT, 0, 0, 0))
    params->idletimeout = ntohl(attr->v.i);
  else if (!reconfig) 
    params->idletimeout = 0;

  /* Filter ID */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_FILTER_ID, 0, 0, 0)) {
    params->filteridlen = attr->l-2;
    memcpy(params->filteridbuf, attr->v.t, attr->l-2);
    params->filteridbuf[attr->l-2] = 0;
  }
  else if (!reconfig) {
    params->filteridlen = 0;
    params->filteridbuf[0] = 0;
  }

  /* Interim interval */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_ACCT_INTERIM_INTERVAL, 0, 0, 0)) {
    params->interim_interval = ntohl(attr->v.i);
    if (params->interim_interval < 60) {
      log_err(0, "Received too small radius Acct-Interim-Interval: %d; resettings to default.",
	      params->interim_interval);
      params->interim_interval = options.definteriminterval;
    } 
  }
  else if (!reconfig)
    params->interim_interval = 0;

  /* Bandwidth up */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_WISPR, 
		      RADIUS_ATTR_WISPR_BANDWIDTH_MAX_UP, 0))
    params->bandwidthmaxup = ntohl(attr->v.i);
  else if (!reconfig)
    params->bandwidthmaxup = 0;
  
  /* Bandwidth down */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_WISPR, 
		      RADIUS_ATTR_WISPR_BANDWIDTH_MAX_DOWN, 0))
    params->bandwidthmaxdown = ntohl(attr->v.i);
  else if (!reconfig)
    params->bandwidthmaxdown = 0;

#ifdef RADIUS_ATTR_CHILLISPOT_BANDWIDTH_MAX_UP
  /* Bandwidth up */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_CHILLISPOT, 
		      RADIUS_ATTR_CHILLISPOT_BANDWIDTH_MAX_UP, 0))
    params->bandwidthmaxup = ntohl(attr->v.i) * 1000;
#endif

#ifdef RADIUS_ATTR_CHILLISPOT_BANDWIDTH_MAX_DOWN
  /* Bandwidth down */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_CHILLISPOT, 
		      RADIUS_ATTR_CHILLISPOT_BANDWIDTH_MAX_DOWN, 0))
    params->bandwidthmaxdown = ntohl(attr->v.i) * 1000;
#endif

  /* Max input octets */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_CHILLISPOT, 
		      RADIUS_ATTR_CHILLISPOT_MAX_INPUT_OCTETS, 0))
    params->maxinputoctets = ntohl(attr->v.i);
  else if (!reconfig)
    params->maxinputoctets = 0;

  /* Max output octets */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_CHILLISPOT, 
		      RADIUS_ATTR_CHILLISPOT_MAX_OUTPUT_OCTETS, 0))
    params->maxoutputoctets = ntohl(attr->v.i);
  else if (!reconfig)
    params->maxoutputoctets = 0;

  /* Max total octets */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_CHILLISPOT, 
		      RADIUS_ATTR_CHILLISPOT_MAX_TOTAL_OCTETS, 0))
    params->maxtotaloctets = ntohl(attr->v.i);
  else if (!reconfig)
    params->maxtotaloctets = 0;

  /* Route Index, look-up by interface name */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC, 
		      RADIUS_VENDOR_CHILLISPOT, 
		      RADIUS_ATTR_CHILLISPOT_ROUTE_TO_INTERFACE, 0)) {
    char name[256];
    memcpy(name, attr->v.t, attr->l-2);
    name[attr->l-2] = 0;
    params->routeidx = tun_name2idx(tun, name);
  }
  else if (!reconfig) {
    params->routeidx = tun->routeidx;
  }

  {
    const char *uamauth = "require-uam-auth";
    const char *uamallowed = "uamallowed=";
    const char *splash = "splash";
    size_t offset = 0;
    int is_splash = 0;

    /* Always reset the per session passthroughs */
    params->pass_through_count = 0;

    while (!radius_getnextattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			       RADIUS_VENDOR_CHILLISPOT, RADIUS_ATTR_CHILLISPOT_CONFIG, 
			       0, &offset)) { 
      size_t len = (size_t)attr->l-2;
      char *val = (char *)attr->v.t;

      if (options.wpaguests && len == strlen(uamauth) && !memcmp(val, uamauth, len)) {
	log_dbg("received wpaguests");
	params->flags |= REQUIRE_UAM_AUTH;
      } 
      else if (len == strlen(splash) && !memcmp(val, splash, strlen(splash))) {
	log_dbg("received splash response");
	params->flags |= REQUIRE_UAM_SPLASH;
	is_splash = 1;
      }
      else if (len > strlen(uamallowed) && !memcmp(val, uamallowed, strlen(uamallowed))) {
	val[len]=0;
	pass_throughs_from_string(params->pass_throughs,
				  SESSION_PASS_THROUGH_MAX,
				  &params->pass_through_count,
				  val + strlen(uamallowed));
      }
    }

    offset = 0;
    params->url[0]=0;
    while (!radius_getnextattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			       RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_REDIRECTION_URL, 
			       0, &offset)) { 
      size_t clen, nlen = (size_t)attr->l-2;
      char *url = (char*)attr->v.t;
      clen = strlen((char*)params->url);

      if (clen + nlen > sizeof(params->url)-1) 
	nlen = sizeof(params->url)-clen-1;

      strncpy((char*)(params->url + clen), url, nlen);
      params->url[nlen+clen]=0;

      if (!splash)
	params->flags |= REQUIRE_REDIRECT;
    }
  }

  /* Session-Terminate-Time */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_WISPR,
		      RADIUS_ATTR_WISPR_SESSION_TERMINATE_TIME, 0)) {
    char attrs[RADIUS_ATTR_VLEN+1];
    struct tm stt;
    int tzhour, tzmin;
    char *tz;
    int result;

    memcpy(attrs, attr->v.t, attr->l-2);
    attrs[attr->l-2] = 0;

    memset(&stt, 0, sizeof(stt));

    result = sscanf(attrs, "%d-%d-%dT%d:%d:%d %d:%d",
		    &stt.tm_year, &stt.tm_mon, &stt.tm_mday,
		    &stt.tm_hour, &stt.tm_min, &stt.tm_sec,
		    &tzhour, &tzmin);

    if (result == 8) { /* Timezone */
      /* tzhour and tzmin is hours and minutes east of GMT */
      /* timezone is defined as seconds west of GMT. Excludes DST */
      stt.tm_year -= 1900;
      stt.tm_mon  -= 1;
      stt.tm_hour -= tzhour; /* Adjust for timezone */
      stt.tm_min  -= tzmin;  /* Adjust for timezone */
      /*      stt.tm_hour += daylight;*/
      /*stt.tm_min  -= (timezone / 60);*/
      tz = getenv("TZ");
      setenv("TZ", "", 1); /* Set environment to UTC */
      tzset();
      params->sessionterminatetime = mktime(&stt);
      if (tz) 
	setenv("TZ", tz, 1); 
      else
	unsetenv("TZ");
      tzset();
    }
    else if (result >= 6) { /* Local time */
      tzset();
      stt.tm_year -= 1900;
      stt.tm_mon  -= 1;
      stt.tm_isdst = -1; /*daylight;*/
      params->sessionterminatetime = mktime(&stt);
    }
    else {
      params->sessionterminatetime = 0;
      log(LOG_WARNING, "Illegal WISPr-Session-Terminate-Time received: %s", attrs);
    }
  }
  else if (!reconfig)
    params->sessionterminatetime = 0;
}

static int chilliauth_cb(struct radius_t *radius,
			 struct radius_packet_t *pack,
			 struct radius_packet_t *pack_req, void *cbp) {
  struct radius_attr_t *attr = NULL;
  size_t offset = 0;

  if (!pack) { 
    log_err(0, "Radius request timed out");
    return 0;
  }

  if ((pack->code != RADIUS_CODE_ACCESS_REJECT) && 
      (pack->code != RADIUS_CODE_ACCESS_CHALLENGE) &&
      (pack->code != RADIUS_CODE_ACCESS_ACCEPT)) {
    log_err(0, "Unknown radius access reply code %d", pack->code);
    return 0;
  }

  /* ACCESS-ACCEPT */
  if (pack->code != RADIUS_CODE_ACCESS_ACCEPT) {
    log_err(0, "Administrative-User Login Failed");
    return 0;
  }

  while (!radius_getnextattr(pack, &attr, 
			     RADIUS_ATTR_VENDOR_SPECIFIC,
			     RADIUS_VENDOR_CHILLISPOT,
			     RADIUS_ATTR_CHILLISPOT_CONFIG, 
			     0, &offset)) {
    char value[RADIUS_ATTR_VLEN+1] = "";
    strncpy(value, (const char *)attr->v.t, attr->l - 2);

    /* build the command line argv here and pass to config parser! */
    /* XXX */
    printf("%s\n", value);
  }

  if (!admin_session.s_state.authenticated) {
    admin_session.s_state.authenticated = 1;
    acct_req(&admin_session, RADIUS_STATUS_TYPE_START);
  }

  return 0;
}

int cb_radius_acct_conf(struct radius_t *radius, 
			struct radius_packet_t *pack,
			struct radius_packet_t *pack_req, void *cbp) {
  struct app_conn_t *appconn = (struct app_conn_t*) cbp;
  if (!appconn) {
    log_err(0,"No peer protocol defined");
    return 0;
  }
  config_radius_session(&appconn->s_params, pack, 1); /*XXX*/
  return 0;
}

/*********************************************************
 *
 * radius callback functions (response from radius server)
 *
 *********************************************************/

/* Radius callback when access accept/reject/challenge has been received */
int cb_radius_auth_conf(struct radius_t *radius, 
			struct radius_packet_t *pack,
			struct radius_packet_t *pack_req, void *cbp) {
  struct radius_attr_t *hisipattr = NULL;
  struct radius_attr_t *lmntattr = NULL;
  struct radius_attr_t *sendattr = NULL;
  struct radius_attr_t *recvattr = NULL;
  struct radius_attr_t *succattr = NULL;
  struct radius_attr_t *policyattr = NULL;
  struct radius_attr_t *typesattr = NULL;

  struct radius_attr_t *eapattr = NULL;
  struct radius_attr_t *stateattr = NULL;
  struct radius_attr_t *classattr = NULL;

  int instance = 0;
  struct in_addr *hisip = NULL;
  int statip = 0;

  struct app_conn_t *appconn = (struct app_conn_t*) cbp;

  if (options.debug)
    log_dbg("Received access request confirmation from radius server\n");
  
  if (!appconn) {
    log_err(0,"No peer protocol defined");
    return 0;
  }

  /* Initialise */
  appconn->s_state.redir.statelen = 0;
  appconn->challen  = 0;
  appconn->sendlen  = 0;
  appconn->recvlen  = 0;
  appconn->lmntlen  = 0;
  

  if (!pack) { /* Timeout */
    log_err(0, "Radius request timed out");
    return dnprot_reject(appconn);
  }

  /* ACCESS-REJECT */
  if (pack->code == RADIUS_CODE_ACCESS_REJECT) {
    if (options.debug)
      log_dbg("Received access reject from radius server");
    config_radius_session(&appconn->s_params, pack, 0); /*XXX*/
    return dnprot_reject(appconn);
  }

  /* Get State */
  if (!radius_getattr(pack, &stateattr, RADIUS_ATTR_STATE, 0, 0, 0)) {
    appconn->s_state.redir.statelen = stateattr->l-2;
    memcpy(appconn->s_state.redir.statebuf, stateattr->v.t, stateattr->l-2);
  }

  /* ACCESS-CHALLENGE */
  if (pack->code == RADIUS_CODE_ACCESS_CHALLENGE) {
    if (options.debug)
      log_dbg("Received access challenge from radius server");

    /* Get EAP message */
    appconn->challen = 0;
    do {
      eapattr=NULL;
      if (!radius_getattr(pack, &eapattr, RADIUS_ATTR_EAP_MESSAGE, 0, 0, instance++)) {
	if ((appconn->challen + eapattr->l-2) > EAP_LEN) {
	  log(LOG_INFO, "EAP message too long");
	  return dnprot_reject(appconn);
	}
	memcpy(appconn->chal+appconn->challen, eapattr->v.t, eapattr->l-2);
	appconn->challen += eapattr->l-2;
      }
    } while (eapattr);
    
    if (!appconn->challen) {
      log(LOG_INFO, "No EAP message found");
      return dnprot_reject(appconn);
    }
    
    return dnprot_challenge(appconn);
  }
  
  /* ACCESS-ACCEPT */
  if (pack->code != RADIUS_CODE_ACCESS_ACCEPT) {
    log_err(0, "Unknown code of radius access request confirmation");
    return dnprot_reject(appconn);
  }

  /* Class */
  if (!radius_getattr(pack, &classattr, RADIUS_ATTR_CLASS, 0, 0, 0)) {
    appconn->s_state.redir.classlen = classattr->l-2;
    memcpy(appconn->s_state.redir.classbuf, classattr->v.t, classattr->l-2);
    /*log_dbg("!!!! CLASSLEN = %d !!!!", appconn->s_state.redir.classlen);*/
  }
  else {
    /*log_dbg("!!!! RESET CLASSLEN !!!!");*/
    appconn->s_state.redir.classlen = 0;
  }

  /* Framed IP address (Optional) */
  if (!radius_getattr(pack, &hisipattr, RADIUS_ATTR_FRAMED_IP_ADDRESS, 0, 0, 0)) {
    if ((hisipattr->l-2) != sizeof(struct in_addr)) {
      log_err(0, "Wrong length of framed IP address");
      return dnprot_reject(appconn);
    }
    hisip = (struct in_addr*) &(hisipattr->v.i);
    statip = 1;
  }
  else {
    hisip = (struct in_addr*) &appconn->reqip.s_addr;
  }

  config_radius_session(&appconn->s_params, pack, 0);

  if (options.dhcpradius) {
    struct dhcp_conn_t *dhcpconn = (struct dhcp_conn_t *)appconn->dnlink;
    struct radius_attr_t *attr = NULL;
    if (dhcpconn) {
      if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC, RADIUS_VENDOR_CHILLISPOT, 
			  RADIUS_ATTR_CHILLISPOT_DHCP_SERVER_NAME, 0)) {
	memcpy(dhcpconn->dhcp_opts.sname, attr->v.t, attr->l-2);
      }
      if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC, RADIUS_VENDOR_CHILLISPOT, 
			  RADIUS_ATTR_CHILLISPOT_DHCP_FILENAME, 0)) {
	memcpy(dhcpconn->dhcp_opts.file, attr->v.t, attr->l-2);
      }
      if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC, RADIUS_VENDOR_CHILLISPOT, 
			  RADIUS_ATTR_CHILLISPOT_DHCP_OPTION, 0)) {
	memcpy(dhcpconn->dhcp_opts.options, attr->v.t, 
	       dhcpconn->dhcp_opts.option_length = attr->l-2);
      }
    }
  }

  if (appconn->s_params.sessionterminatetime) {
    time_t timenow = mainclock;
    if (timenow > appconn->s_params.sessionterminatetime) {
      log(LOG_WARNING, "WISPr-Session-Terminate-Time in the past received, rejecting");
      return dnprot_reject(appconn);
    }
  }

#ifdef LEAKY_BUCKET
  if (appconn->s_params.bandwidthmaxup) {
#ifdef BUCKET_SIZE
    appconn->s_state.bucketupsize = BUCKET_SIZE;
#else
    appconn->s_state.bucketupsize = appconn->s_params.bandwidthmaxup / 8000 * BUCKET_TIME;
    if (appconn->s_state.bucketupsize < BUCKET_SIZE_MIN) 
      appconn->s_state.bucketupsize = BUCKET_SIZE_MIN;
#endif
  }
#endif
  
#ifdef LEAKY_BUCKET
  if (appconn->s_params.bandwidthmaxdown) {
#ifdef BUCKET_SIZE
    appconn->s_state.bucketdownsize = BUCKET_SIZE;
#else
    appconn->s_state.bucketdownsize = appconn->s_params.bandwidthmaxdown / 8000 * BUCKET_TIME;
    if (appconn->s_state.bucketdownsize < BUCKET_SIZE_MIN) 
      appconn->s_state.bucketdownsize = BUCKET_SIZE_MIN;
#endif
  }
#endif

  /* EAP Message */
  appconn->challen = 0;
  do {
    eapattr=NULL;
    if (!radius_getattr(pack, &eapattr, RADIUS_ATTR_EAP_MESSAGE, 0, 0, 
			instance++)) {
      if ((appconn->challen + eapattr->l-2) > EAP_LEN) {
	log(LOG_INFO, "EAP message too long");
	return dnprot_reject(appconn);
      }
      memcpy(appconn->chal+appconn->challen,
	     eapattr->v.t, eapattr->l-2);
      appconn->challen += eapattr->l-2;
    }
  } while (eapattr);

  /* Get sendkey */
  if (!radius_getattr(pack, &sendattr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_MS,
		      RADIUS_ATTR_MS_MPPE_SEND_KEY, 0)) {
    if (radius_keydecode(radius, appconn->sendkey, RADIUS_ATTR_VLEN, &appconn->sendlen, 
			 (uint8_t *)&sendattr->v.t, sendattr->l-2, 
			 pack_req->authenticator,
			 radius->secret, radius->secretlen)) {
      log_err(0, "radius_keydecode() failed!");
      return dnprot_reject(appconn);
    }
  }
    
  /* Get recvkey */
  if (!radius_getattr(pack, &recvattr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_MS,
		      RADIUS_ATTR_MS_MPPE_RECV_KEY, 0)) {
    if (radius_keydecode(radius, appconn->recvkey, RADIUS_ATTR_VLEN, &appconn->recvlen, 
			 (uint8_t *)&recvattr->v.t, recvattr->l-2, 
			 pack_req->authenticator,
			 radius->secret, radius->secretlen) ) {
      log_err(0, "radius_keydecode() failed!");
      return dnprot_reject(appconn);
    }
  }

  /* Get LMNT keys */
  if (!radius_getattr(pack, &lmntattr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_MS,
		      RADIUS_ATTR_MS_CHAP_MPPE_KEYS, 0)) {

    /* TODO: Check length of vendor attributes */
    if (radius_pwdecode(radius, appconn->lmntkeys, RADIUS_MPPEKEYSSIZE,
			&appconn->lmntlen, (uint8_t *)&lmntattr->v.t,
			lmntattr->l-2, pack_req->authenticator,
			radius->secret, radius->secretlen)) {
      log_err(0, "radius_pwdecode() failed");
      return dnprot_reject(appconn);
    }
  }
  
  /* Get encryption policy */
  if (!radius_getattr(pack, &policyattr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_MS, 
		      RADIUS_ATTR_MS_MPPE_ENCRYPTION_POLICY, 0)) {
    appconn->policy = ntohl(policyattr->v.i);
  }
  
  /* Get encryption types */
  if (!radius_getattr(pack, &typesattr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_MS, 
		      RADIUS_ATTR_MS_MPPE_ENCRYPTION_TYPES, 0)) {
    appconn->types = ntohl(typesattr->v.i);
  }
  

  /* Get MS_Chap_v2 SUCCESS */
  if (!radius_getattr(pack, &succattr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_MS,
		      RADIUS_ATTR_MS_CHAP2_SUCCESS, 0)) {
    if ((succattr->l-5) != MS2SUCCSIZE) {
      log_err(0, "Wrong length of MS-CHAP2 success: %d", succattr->l-5);
      return dnprot_reject(appconn);
    }
    memcpy(appconn->ms2succ, ((void*)&succattr->v.t)+3, MS2SUCCSIZE);
  }

  /* for the admin session */
  if (appconn->is_adminsession) {
    return chilliauth_cb(radius, pack, pack_req, cbp);
  }

  switch(appconn->authtype) {

  case PAP_PASSWORD:
    appconn->policy = 0; /* TODO */
    break;

  case EAP_MESSAGE:
    if (!appconn->challen) {
      log(LOG_INFO, "No EAP message found");
      return dnprot_reject(appconn);
    }
    break;

  case CHAP_DIGEST_MD5:
    appconn->policy = 0; /* TODO */
    break;

  case CHAP_MICROSOFT:
    if (!lmntattr) {
      log(LOG_INFO, "No MPPE keys found");
      return dnprot_reject(appconn);
      }
    if (!succattr) {
      log_err(0, "No MS-CHAP2 success found");
      return dnprot_reject(appconn);
    }
    break;

  case CHAP_MICROSOFT_V2:
    if (!sendattr) {
      log(LOG_INFO, "No MPPE sendkey found");
      return dnprot_reject(appconn);
    }
    
    if (!recvattr) {
      log(LOG_INFO, "No MPPE recvkey found");
      return dnprot_reject(appconn);
    }
    
    break;

  default:
    log_err(0, "Unknown authtype");
    return dnprot_reject(appconn);
  }
  
  return upprot_getip(appconn, hisip, statip);
}


/* Radius callback when coa or disconnect request has been received */
int cb_radius_coa_ind(struct radius_t *radius, struct radius_packet_t *pack,
		      struct sockaddr_in *peer) {
  struct app_conn_t *appconn;
  struct radius_attr_t *uattr = NULL;
  struct radius_attr_t *sattr = NULL;
  struct radius_packet_t radius_pack;
  int found = 0;
  int iscoa = 0;

  if (options.debug)
    log_dbg("Received coa or disconnect request\n");
  
  if (pack->code != RADIUS_CODE_DISCONNECT_REQUEST &&
      pack->code != RADIUS_CODE_COA_REQUEST) {
    log_err(0, "Radius packet not supported: %d,\n", pack->code);
    return -1;
  }

  iscoa = pack->code == RADIUS_CODE_COA_REQUEST;

  /* Get username */
  if (radius_getattr(pack, &uattr, RADIUS_ATTR_USER_NAME, 0, 0, 0)) {
    log_warn(0, "Username must be included in disconnect request");
    return -1;
  }

  if (!radius_getattr(pack, &sattr, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0))
    if (options.debug) 
      log_dbg("Session-id present in disconnect. Only disconnecting that session\n");


  if (options.debug)
    log_dbg("Looking for session [username=%.*s,sessionid=%.*s]", 
	    uattr->l-2, uattr->v.t, sattr ? sattr->l-2 : 3, sattr ? (char*)sattr->v.t : "all");
  
  for (appconn = firstusedconn; appconn; appconn = appconn->next) {
    if (!appconn->inuse) { log_err(0, "Connection with inuse == 0!"); }

    if ((appconn->s_state.authenticated) && 
	(strlen(appconn->s_state.redir.username) == uattr->l-2 && 
	 !memcmp(appconn->s_state.redir.username, uattr->v.t, uattr->l-2)) &&
	(!sattr || 
	 (strlen(appconn->s_state.sessionid) == sattr->l-2 && 
	  !strncasecmp(appconn->s_state.sessionid, (char*)sattr->v.t, sattr->l-2)))) {

      if (options.debug)
	log_dbg("Found session\n");

      if (iscoa)
	config_radius_session(&appconn->s_params, pack, 0);
      else
	terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_ADMIN_RESET);

      found = 1;
    }
  }

  if (found) {
    if (radius_default_pack(radius, &radius_pack, 
			    iscoa ? RADIUS_CODE_COA_ACK : RADIUS_CODE_DISCONNECT_ACK)) {
      log_err(0, "radius_default_pack() failed");
      return -1;
    }
  }
  else {
    if (radius_default_pack(radius, &radius_pack, 
			    iscoa ? RADIUS_CODE_COA_NAK : RADIUS_CODE_DISCONNECT_NAK)) {
      log_err(0, "radius_default_pack() failed");
      return -1;
    }
  }

  radius_pack.id = pack->id;
  (void) radius_coaresp(radius, &radius_pack, peer, pack->authenticator);

  return 0;
}


/***********************************************************
 *
 * dhcp callback functions
 *
 ***********************************************************/

/* DHCP callback for allocating new IP address */
/* In the case of WPA it is allready allocated,
 * for UAM address is allocated before authentication */
int cb_dhcp_request(struct dhcp_conn_t *conn, struct in_addr *addr, 
		    struct dhcp_fullpacket_t *dhcp_pkt, size_t dhcp_len) {
  struct app_conn_t *appconn = conn->peer;
  struct ippoolm_t *ipm;

  if (options.debug) 
    log_dbg("DHCP request for IP address");

  if (!appconn) {
    log_err(0, "Peer protocol not defined");
    return -1;
  }

  appconn->reqip.s_addr = addr->s_addr; /* Save for MAC auth later */

  /* If IP address is allready allocated: Fill it in */
  if (appconn->uplink) {

    ipm = (struct ippoolm_t*) appconn->uplink;

  } else if ((options.macauth) && 
	     (appconn->dnprot == DNPROT_DHCP_NONE)) {
    
    appconn->dnprot = DNPROT_MAC;

    macauth_radius(appconn, dhcp_pkt, dhcp_len);

    return -1;

  } else if ((options.macoklen) && 
	     (appconn->dnprot == DNPROT_DHCP_NONE) &&
	     !maccmp(conn->hismac)) {
    
    appconn->dnprot = DNPROT_MAC;

    if (options.macallowlocal) {
      upprot_getip(appconn, &appconn->reqip, 0);/**/
      dnprot_accept(appconn);
    } else {
      macauth_radius(appconn, dhcp_pkt, dhcp_len);
    }

    return -1;

  } else {

    if (appconn->dnprot != DNPROT_DHCP_NONE) {
      log_warn(0, "Requested IP address when already allocated");
    }
    
    /* Allocate dynamic IP address */
    /*XXX    if (ippool_newip(ippool, &ipm, &appconn->reqip, 0)) {*/
    if (newip(&ipm, &appconn->reqip)) {
      log_err(0, "Failed allocate dynamic IP address");
      return -1;
    }

    appconn->hisip.s_addr = ipm->addr.s_addr;
    
    log(LOG_NOTICE, "Client MAC=%.2X-%.2X-%.2X-%.2X-%.2X-%.2X assigned IP %s" , 
	conn->hismac[0], conn->hismac[1], 
	conn->hismac[2], conn->hismac[3],
	conn->hismac[4], conn->hismac[5], 
	inet_ntoa(appconn->hisip));

    /* TODO: Too many "listen" and "our" addresses hanging around */
    appconn->ourip.s_addr = options.dhcplisten.s_addr;
    
    appconn->uplink =  ipm;
    ipm->peer   = appconn; 
  }
  
  dhcp_set_addrs(conn, 
		 &ipm->addr, &options.mask, 
		 &appconn->ourip, &appconn->mask,
		 &options.dns1, &options.dns2, 
		 options.domain);

  conn->authstate = DHCP_AUTH_DNAT;

  /* If IP was requested before authentication it was UAM */
  if (appconn->dnprot == DNPROT_DHCP_NONE)
    appconn->dnprot = DNPROT_UAM;

  return 0;
}

/* DHCP callback for establishing new connection */
int cb_dhcp_connect(struct dhcp_conn_t *conn) {
  struct app_conn_t *appconn;

  log(LOG_NOTICE, "New DHCP request from MAC=%.2X-%.2X-%.2X-%.2X-%.2X-%.2X" , 
      conn->hismac[0], conn->hismac[1], 
      conn->hismac[2], conn->hismac[3],
      conn->hismac[4], conn->hismac[5]);
  
  if (options.debug) 
    log_dbg("New DHCP connection established");

  /* Allocate new application connection */
  if (newconn(&appconn)) {
    log_err(0, "Failed to allocate connection");
    return 0;
  }

  appconn->dnlink =  conn;
  appconn->dnprot =  DNPROT_DHCP_NONE;
  conn->peer = appconn;

  appconn->net.s_addr = options.net.s_addr;
  appconn->mask.s_addr = options.mask.s_addr;
  appconn->dns1.s_addr = options.dns1.s_addr;
  appconn->dns2.s_addr = options.dns2.s_addr;

  memcpy(appconn->hismac, conn->hismac, PKT_ETH_ALEN);
  memcpy(appconn->ourmac, conn->ourmac, PKT_ETH_ALEN);
  
  set_sessionid(appconn);

  conn->authstate = DHCP_AUTH_NONE; /* TODO: Not yet authenticated */

  return 0;
}

int cb_dhcp_getinfo(struct dhcp_conn_t *conn, bstring b, int fmt) {
  time_t timenow = mainclock;
  struct app_conn_t *appconn;
  uint32_t sessiontime = 0;
  uint32_t idletime = 0;

  if (!conn->peer) return 2;
  appconn = (struct app_conn_t*) conn->peer;
  if (!appconn->inuse) return 2;

  if (appconn->s_state.authenticated) {
    sessiontime = timenow - appconn->s_state.start_time;
    idletime    = timenow - appconn->s_state.last_time;
  }

  switch(fmt) {
  case LIST_JSON_FMT:
    if (appconn->s_state.authenticated)
      session_json_fmt(&appconn->s_state, &appconn->s_params, b, 0);
    break;
  default:
    {
      bstring tmp = bfromcstr("");
      bassignformat(tmp, " %.*s %d %.*s %d/%d %d/%d %.*s", 
		    appconn->s_state.sessionid[0] ? strlen(appconn->s_state.sessionid) : 1,
		    appconn->s_state.sessionid[0] ? appconn->s_state.sessionid : "-",
		    appconn->s_state.authenticated,
		    appconn->s_state.redir.username[0] ? strlen(appconn->s_state.redir.username) : 1,
		    appconn->s_state.redir.username[0] ? appconn->s_state.redir.username : "-",
		    sessiontime, (int)appconn->s_params.sessiontimeout,
		    idletime, (int)appconn->s_params.idletimeout,
		    appconn->s_state.redir.userurl[0] ? strlen(appconn->s_state.redir.userurl) : 1,
		    appconn->s_state.redir.userurl[0] ? appconn->s_state.redir.userurl : "-");
      bconcat(b, tmp);
      bdestroy(tmp);
    }
  }
  return 0;
}

int terminate_appconn(struct app_conn_t *appconn, int terminate_cause) {
  if (appconn->s_state.authenticated == 1) { /* Only send accounting if logged in */
    dnprot_terminate(appconn);
    appconn->s_state.terminate_cause = terminate_cause;
    acct_req(appconn, RADIUS_STATUS_TYPE_STOP);

    /* should memory be cleared here?? */
    memset(&appconn->s_params, 0, sizeof(appconn->s_params));
    set_sessionid(appconn);
  }
  return 0;
}

/* Callback when a dhcp connection is deleted */
int cb_dhcp_disconnect(struct dhcp_conn_t *conn, int term_cause) {
  struct app_conn_t *appconn;

  log(LOG_INFO, "DHCP addr released by MAC=%.2X-%.2X-%.2X-%.2X-%.2X-%.2X IP=%s", 
      conn->hismac[0], conn->hismac[1], 
      conn->hismac[2], conn->hismac[3],
      conn->hismac[4], conn->hismac[5], 
      inet_ntoa(conn->hisip));
  
  if (options.debug) log_dbg("DHCP connection removed");

  if (!conn->peer) return 0; /* No appconn allocated. Stop here */
  appconn = (struct app_conn_t*) conn->peer;

  if ((appconn->dnprot != DNPROT_DHCP_NONE) &&
      (appconn->dnprot != DNPROT_UAM) &&
      (appconn->dnprot != DNPROT_MAC) &&
      (appconn->dnprot != DNPROT_WPA) &&
      (appconn->dnprot != DNPROT_EAPOL))  {
    return 0; /* DNPROT_WPA and DNPROT_EAPOL are unaffected by dhcp release? */
  }

  terminate_appconn(appconn, 
		    term_cause ? term_cause : 
		    appconn->s_state.terminate_cause ? 
		    appconn->s_state.terminate_cause :
		    RADIUS_TERMINATE_CAUSE_LOST_CARRIER);

  /* ALPAPAD */
  if (appconn->uplink) {
    if (options.uamanyip) {
      struct ippoolm_t *member = (struct ippoolm_t *) appconn->uplink;
      if (member->inuse  == 2) {
	struct in_addr mask;
	mask.s_addr = 0xffffffff;
	log_dbg("Removing route: %s %d\n", inet_ntoa(member->addr),
		net_del_route(&member->addr, &appconn->ourip, &mask));
      }
    }
    if (ippool_freeip(ippool, (struct ippoolm_t *) appconn->uplink)) {
      log_err(0, "ippool_freeip() failed!");
    }
  }
  
  freeconn(appconn);

  return 0;
}


/* Callback for receiving messages from dhcp */
int cb_dhcp_data_ind(struct dhcp_conn_t *conn, void *pack, size_t len) {
  struct app_conn_t *appconn = conn->peer;
  /*struct dhcp_ethhdr_t *ethh = (struct dhcp_ethhdr_t *)pack;*/
  struct pkt_ipphdr_t *ipph = (struct pkt_ipphdr_t *)((char*)pack + PKT_ETH_HLEN);

  /*if (options.debug)
    log_dbg("cb_dhcp_data_ind. Packet received. DHCP authstate: %d\n", 
    conn->authstate);*/

  if (ipph->saddr != conn->hisip.s_addr) {
    if (options.debug) 
      log_dbg("Received packet with spoofed source!");
    return 0;
  }

  if (!appconn) {
    log_err(0, "No peer protocol defined");
    return -1;
  }

  switch (appconn->dnprot) {
  case DNPROT_NULL:
  case DNPROT_DHCP_NONE:
    return -1;

  case DNPROT_UAM:
  case DNPROT_WPA:
  case DNPROT_MAC:
  case DNPROT_EAPOL:
    break;

  default:
    log_err(0, "Unknown downlink protocol: %d", appconn->dnprot);
    break;
  }

  /* If the ip dst is uamlisten and pdst is uamport we won't call leaky_bucket,
  *  and we always send these packets through to the tun/tap interface (index 0) 
  */
  if (ipph->daddr  == options.uamlisten.s_addr && 
      (ipph->dport == htons(options.uamport) ||
       ipph->dport == htons(options.uamuiport)))
    return tun_encaps(tun, pack, len, 0);
  
  if (appconn->s_state.authenticated == 1) {

#ifndef LEAKY_BUCKET
    appconn->s_state.last_time = mainclock;
#endif

#ifdef LEAKY_BUCKET
#ifndef COUNT_UPLINK_DROP
    if (leaky_bucket(appconn, len, 0)) return 0;
#endif
#endif
    if (options.swapoctets) {
      appconn->s_state.input_packets++;
      appconn->s_state.input_octets +=len;
      if (admin_session.s_state.authenticated) {
	admin_session.s_state.input_packets++;
	admin_session.s_state.input_octets+=len;
      }
    } else {
      appconn->s_state.output_packets++;
      appconn->s_state.output_octets +=len;
      if (admin_session.s_state.authenticated) {
	admin_session.s_state.output_packets++;
	admin_session.s_state.output_octets+=len;
      }
    }
#ifdef LEAKY_BUCKET
#ifdef COUNT_UPLINK_DROP
    if (leaky_bucket(appconn, len, 0)) return 0;
#endif
#endif
  }

  return tun_encaps(tun, pack, len, appconn->s_params.routeidx);
}

/* Callback for receiving messages from eapol */
int cb_dhcp_eap_ind(struct dhcp_conn_t *conn, void *pack, size_t len) {
  struct eap_packet_t *eap = (struct eap_packet_t *)pack;
  struct app_conn_t *appconn = conn->peer;
  struct radius_packet_t radius_pack;
  char mac[MACSTRLEN+1];
  size_t offset;

  if (options.debug) log_dbg("EAP Packet received");

  /* If this is the first EAPOL authentication request */
  if ((appconn->dnprot == DNPROT_DHCP_NONE) || 
      (appconn->dnprot == DNPROT_EAPOL)) {
    if ((eap->code == 2) && /* Response */
	(eap->type == 1) && /* Identity */
	(len > 5) &&        /* Must be at least 5 octets */
	((len - 5) <= USERNAMESIZE )) {
      memcpy(appconn->s_state.redir.username, eap->payload, len - 5); 
      appconn->dnprot = DNPROT_EAPOL;
      appconn->authtype = EAP_MESSAGE;
    }
    else if (appconn->dnprot == DNPROT_DHCP_NONE) {
      log_err(0, "Initial EAP response was not a valid identity response!");
      return 0;
    }
  }

  /* Return if not EAPOL */
  if (appconn->dnprot != DNPROT_EAPOL) {
    log_warn(0, "Received EAP message, processing for authentication");
    appconn->dnprot = DNPROT_EAPOL;
    return 0;
  }
  
  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REQUEST)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }

  /* Build up radius request */
  radius_pack.code = RADIUS_CODE_ACCESS_REQUEST;

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
			(uint8_t*) appconn->s_state.redir.username, 
			strlen(appconn->s_state.redir.username));

  if (appconn->s_state.redir.statelen) {
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_STATE, 0, 0, 0,
		   appconn->s_state.redir.statebuf,
		   appconn->s_state.redir.statelen);
  }
  
  /* Include EAP (if present) */
  offset = 0;
  while (offset < len) {
    size_t eaplen;

    if ((len - offset) > RADIUS_ATTR_VLEN)
      eaplen = RADIUS_ATTR_VLEN;
    else
      eaplen = len - offset;

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_EAP_MESSAGE, 0, 0, 0,
		   pack + offset, eaplen);

    offset += eaplen;
  } 
  
  if (len)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		   0, 0, 0, NULL, RADIUS_MD5LEN);
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		 options.radiusnasporttype, NULL, 0);
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		 appconn->unit, NULL, 0);
  
  radius_addnasip(radius, &radius_pack);

  snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	   appconn->hismac[0], appconn->hismac[1],
	   appconn->hismac[2], appconn->hismac[3],
	   appconn->hismac[4], appconn->hismac[5]);
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0,
		 (uint8_t*) mac, MACSTRLEN);
  
  radius_addcalledstation(radius, &radius_pack);
  
  /* Include NAS-Identifier if given in configuration options */
  if (options.radiusnasid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
		   (uint8_t*) options.radiusnasid,
		   strlen(options.radiusnasid));
  
  return radius_req(radius, &radius_pack, appconn);
}


/***********************************************************
 *
 * uam message handling functions
 *
 ***********************************************************/

int static uam_msg(struct redir_msg_t *msg) {

  struct ippoolm_t *ipm;
  struct app_conn_t *appconn = NULL;
  struct dhcp_conn_t* dhcpconn;

  if (ippool_getip(ippool, &ipm, &msg->mdata.addr)) {
    if (options.debug) 
      log_dbg("UAM login with unknown IP address: %s", inet_ntoa(msg->mdata.addr));
    return 0;
  }

  if ((appconn  = (struct app_conn_t *)ipm->peer)        == NULL || 
      (dhcpconn = (struct dhcp_conn_t *)appconn->dnlink) == NULL) {
    log_err(0, "No peer protocol defined");
    return 0;
  }

  if (msg->mdata.opt & REDIR_MSG_OPT_REDIR)
    memcpy(&appconn->s_state.redir, &msg->mdata.redir, sizeof(msg->mdata.redir));

  if (msg->mdata.opt & REDIR_MSG_OPT_PARAMS)
    memcpy(&appconn->s_params, &msg->mdata.params, sizeof(msg->mdata.params));

  switch(msg->mtype) {

  case REDIR_LOGIN:
    if (appconn->uamabort) {
      log_info("UAM login from username=%s IP=%s was aborted!", 
	       msg->mdata.redir.username, inet_ntoa(appconn->hisip));
      appconn->uamabort = 0;
      return 0;
    }

    log_info("Successful UAM login from username=%s IP=%s", 
	     msg->mdata.redir.username, inet_ntoa(appconn->hisip));
    
    /* Initialise */
    appconn->s_params.routeidx = tun->routeidx;
    appconn->s_state.redir.statelen = 0;
    appconn->challen  = 0;
    appconn->sendlen  = 0;
    appconn->recvlen  = 0;
    appconn->lmntlen  = 0;
    
    memcpy(appconn->hismac, dhcpconn->hismac, PKT_ETH_ALEN);
    memcpy(appconn->ourmac, dhcpconn->ourmac, PKT_ETH_ALEN);
    
    appconn->policy = 0; /* TODO */

#ifdef LEAKY_BUCKET
#ifdef BUCKET_SIZE
    appconn->s_state.bucketupsize = BUCKET_SIZE;
#else
    appconn->s_state.bucketupsize = appconn->s_params.bandwidthmaxup / 8000 * BUCKET_TIME;
    if (appconn->s_state.bucketupsize < BUCKET_SIZE_MIN) 
      appconn->s_state.bucketupsize = BUCKET_SIZE_MIN;
#endif
#endif

#ifdef LEAKY_BUCKET
#ifdef BUCKET_SIZE
    appconn->s_state.bucketdownsize = BUCKET_SIZE;
#else
    appconn->s_state.bucketdownsize = appconn->s_params.bandwidthmaxdown / 8000 * BUCKET_TIME;
    if (appconn->s_state.bucketdownsize < BUCKET_SIZE_MIN) 
      appconn->s_state.bucketdownsize = BUCKET_SIZE_MIN;
#endif
#endif

    return upprot_getip(appconn, NULL, 0);

  case REDIR_LOGOUT:

    log_info("Received UAM logoff from username=%s IP=%s",
	     appconn->s_state.redir.username, inet_ntoa(appconn->hisip));

    if (options.debug)
      log_dbg("Received logoff from UAM\n");

    if (appconn->s_state.authenticated == 1) {
      terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_USER_REQUEST);
      appconn->s_state.uamtime = 0;
      appconn->s_params.sessiontimeout = 0;
      appconn->s_params.idletimeout = 0;
    }

    appconn->s_state.uamtime = mainclock;
    dhcpconn->authstate = DHCP_AUTH_DNAT;
    appconn->uamabort = 0;

    break;

  case REDIR_ABORT:
    
    log_info("Received UAM abort from IP=%s", inet_ntoa(appconn->hisip));

    appconn->uamabort = 1; /* Next login will be aborted */
    appconn->s_state.uamtime = 0;  /* Force generation of new challenge */
    dhcpconn->authstate = DHCP_AUTH_DNAT;

    terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_USER_REQUEST);

    break;

  case REDIR_CHALLENGE:
    appconn->s_state.uamtime = mainclock;
    appconn->uamabort = 0;
    break;

  case REDIR_NOTYET:
    break;
  }

  return 0;
}

static int cmdsock_accept(int sock) {
  struct sockaddr_un remote; 
  struct cmdsock_request req;

  bstring s = 0;
  size_t len;
  int csock;
  int rval = 0;

  if (options.debug) 
    log_dbg("Processing cmdsock request...\n");

  len = sizeof(remote);
  if ((csock = accept(sock, (struct sockaddr *)&remote, &len)) == -1) {
    perror("cmdsock_accept()/accept()");
    return -1;
  }

  if (read(csock, &req, sizeof(req)) != sizeof(req)) {
    perror("cmdsock_accept()/read()");
    close(csock);
    return -1;
  }

  switch(req.type) {

  case CMDSOCK_DHCP_LIST:
    s = bfromcstr("");
    if (dhcp) dhcp_list(dhcp, s, 0, 0,
			req.options & CMDSOCK_OPT_JSON ? 
			LIST_JSON_FMT : LIST_SHORT_FMT);
    write(csock, s->data, s->slen);
    break;
    
  case CMDSOCK_DHCP_DROP:
  case CMDSOCK_DHCP_RELEASE:
    if (dhcp) dhcp_release_mac(dhcp, req.data.mac, RADIUS_TERMINATE_CAUSE_ADMIN_RESET);
    break;

  case CMDSOCK_LIST:
    s = bfromcstr("");
    if (dhcp) dhcp_list(dhcp, s, 0, 0,
			req.options & CMDSOCK_OPT_JSON ? 
			LIST_JSON_FMT : LIST_LONG_FMT);
    write(csock, s->data, s->slen);
    break;

  case CMDSOCK_SHOW:
    /*ToDo*/
    break;

  case CMDSOCK_ROUTE_SET:
    {
      struct dhcp_conn_t *conn = dhcp->firstusedconn;
      log_dbg("looking to authorized session %s",inet_ntoa(req.data.sess.ip));
      while (conn && conn->inuse) {
	if (conn->peer) {
	  struct app_conn_t * appconn = (struct app_conn_t*)conn->peer;
	  if (!memcmp(appconn->hismac, req.data.mac, 6)) {
	    log_dbg("routeidx %s %d",appconn->s_state.sessionid, req.data.sess.params.routeidx);
	    appconn->s_params.routeidx = req.data.sess.params.routeidx;
	    break;
	  }
	}
	conn = conn->next;
      }
    }
    /* drop through */
  case CMDSOCK_ROUTE:
    {
      int i;
      bstring b = bfromcstr("routes:\n");
      write(csock, b->data, b->slen);
      for (i=0; i<tun->_interface_count; i++) {
	bassignformat(b, "idx: %d dev: %s%s\n", 
		      i, tun->_interfaces[i].devname,
		      i == 0 ? " (tun/tap)":"");
	write(csock, b->data, b->slen);
      }

      { 
	struct dhcp_conn_t *conn = dhcp->firstusedconn;
	bassignformat(b, "subscribers:\n");
	write(csock, b->data, b->slen);
	while (conn) {
	  struct app_conn_t *appconn = (struct app_conn_t *)conn->peer;
	  bassignformat(b, "mac: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X -> idx: %d\n", 
			appconn->hismac[0], appconn->hismac[1],
			appconn->hismac[2], appconn->hismac[3],
			appconn->hismac[4], appconn->hismac[5],
			appconn->s_params.routeidx);
	  write(csock, b->data, b->slen);
	  conn = conn->next;
	}
      }
      bdestroy(b);
    }
    break;

  case CMDSOCK_AUTHORIZE:
    if (dhcp) {
      struct dhcp_conn_t *dhcpconn = dhcp->firstusedconn;
      log_dbg("looking to authorized session %s",inet_ntoa(req.data.sess.ip));
      while (dhcpconn && dhcpconn->inuse) {
	if (dhcpconn->peer) {
	  struct app_conn_t * appconn = (struct app_conn_t*) dhcpconn->peer;
	  if (  (req.data.sess.ip.s_addr == 0    || appconn->hisip.s_addr == req.data.sess.ip.s_addr) &&
		(req.data.sess.sessionid[0] == 0 || !strcmp(appconn->s_state.sessionid,req.data.sess.sessionid))
		){
	    char *uname = req.data.sess.username;
	    log_dbg("remotely authorized session %s",appconn->s_state.sessionid);
	    memcpy(&appconn->s_params, &req.data.sess.params, sizeof(req.data.sess.params));
	    if (uname[0]) strncpy(appconn->s_state.redir.username, uname, USERNAMESIZE);
	    dnprot_accept(appconn);
	    break;
	  }
	}
	dhcpconn = dhcpconn->next;
      }
    }
    break;

  default:
    perror("unknown command");
    close(csock);
    rval = -1;
  }

  if (s) bdestroy(s);
  shutdown(csock, 2);
  close(csock);

  return rval;
}

/* Function that will create and write a status file in statedir*/
int printstatus(struct app_conn_t *appconn) {
  char *statedir = options.statedir ? options.statedir : DEFSTATEDIR;
  struct app_conn_t *apptemp;
  FILE *file;
  char filedest[512];
  time_t timenow = mainclock;
  struct stat statbuf;

  if (!options.usestatusfile) 
    return 0;

  if (strlen(statedir)>sizeof(filedest)-1) 
    return -1;

  if (stat(statedir, &statbuf)) { 
    log_err(errno, "statedir (%s) does not exist", statedir); 
    return -1; 
  }

  if (!S_ISDIR(statbuf.st_mode)) { 
    log_err(0, "statedir (%s) not a directory", statedir); 
    return -1; 
  }

  strcpy(filedest, statedir);
  strcat(filedest, "/chillispot.state");

  file = fopen(filedest, "w");
  if (!file) { log_err(errno, "could not open file %s", filedest); return -1; }
  fprintf(file, "#Version:1.1\n");
  fprintf(file, "#SessionID = SID\n#Start-Time = ST\n");
  fprintf(file, "#SessionTimeOut = STO\n#SessionTerminateTime = STT\n");
  fprintf(file, "#Timestamp: %d\n", timenow);
  fprintf(file, "#User, IP, MAC, SID, ST, STO, STT\n");
  if(appconn == NULL)
  {
    fclose(file);
    return 0;
  }
  apptemp = appconn;
  while(apptemp != NULL)
  {
    if(apptemp->s_state.authenticated==1)
    {
      fprintf(file, "%s, %s, %.2X-%.2X-%.2X-%.2X-%.2X-%.2X, %s, %d, %d, %d\n",
	apptemp->s_state.redir.username,
	inet_ntoa(apptemp->hisip),
	apptemp->hismac[0], apptemp->hismac[1],
	apptemp->hismac[2], apptemp->hismac[3],
	apptemp->hismac[4], apptemp->hismac[5],
	apptemp->s_state.sessionid,
	apptemp->s_state.start_time,
	apptemp->s_params.sessiontimeout,
	apptemp->s_params.sessionterminatetime);
    }
    apptemp = apptemp->prev;
  }
  apptemp = appconn->next;
  while(apptemp != NULL)
  {
    if(apptemp->s_state.authenticated==1)
    {
      fprintf(file, "%s, %s, %.2X-%.2X-%.2X-%.2X-%.2X-%.2X, %s, %d, %d, %d\n",
	apptemp->s_state.redir.username,
	inet_ntoa(apptemp->hisip),
	apptemp->hismac[0], apptemp->hismac[1],
	apptemp->hismac[2], apptemp->hismac[3],
	apptemp->hismac[4], apptemp->hismac[5],
	apptemp->s_state.sessionid,
        apptemp->s_state.start_time,
	apptemp->s_params.sessiontimeout,
	apptemp->s_params.sessionterminatetime);
    }
    apptemp = apptemp->next;
  }
  fclose(file);
  return 0;
}

static void fixup_options() {
  /*
   * If we have no nasmac configured, lets default it here, after creating the dhcp
   */
  if (!options.nasmac) {
    char mac[24];

    sprintf(mac, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", 
	    dhcp->ipif.hwaddr[0],dhcp->ipif.hwaddr[1],dhcp->ipif.hwaddr[2],
	    dhcp->ipif.hwaddr[3],dhcp->ipif.hwaddr[4],dhcp->ipif.hwaddr[5]);
    
    options.nasmac = strdup(mac);
  }

}

int chilli_main(int argc, char **argv) {
  
  int maxfd = 0;	        /* For select() */
  fd_set fds;			/* For select() */
  struct timeval idleTime;	/* How long to select() */
  int status;
  int msgresult;

  struct redir_msg_t msg;
  struct sigaction act;
  /*  struct itimerval itval; */
  int lastSecond = 0, thisSecond;

  int cmdsock = -1;

  /* open a connection to the syslog daemon */
  /*openlog(PACKAGE, LOG_PID, LOG_DAEMON);*/
  openlog(PACKAGE, (LOG_PID | LOG_PERROR), LOG_DAEMON);

  /* Process options given in configuration file and command line */
  if (process_options(argc, argv, 0))
    exit(1);

  /* foreground                                                   */
  /* If flag not given run as a daemon                            */
  if (!options.foreground) {
    /* Close the standard file descriptors. */
    /* Is this really needed ? */
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
    freopen("/dev/null", "r", stdin);
    if (daemon(1, 1)) {
      log_err(errno, "daemon() failed!");
    }
  } 

  if (options.logfacility<0||options.logfacility>LOG_NFACILITIES)
    options.logfacility=LOG_FAC(LOG_LOCAL6);

  closelog(); 
  openlog(PACKAGE, LOG_PID, (options.logfacility<<3));
  
  /* This has to be done after we have our final pid */
  log_pid((options.pidfile && *options.pidfile) ? options.pidfile : DEFPIDFILE);

  if (options.debug) 
    log_dbg("ChilliSpot version %s started.\n", VERSION);

  syslog(LOG_INFO, "CoovaChilli(ChilliSpot) %s. Copyright 2002-2005 Mondru AB. Licensed under GPL. "
	 "Copyright 2006-2008 David Bird <dbird@acm.org>. Licensed under GPL. "
	 "See http://coova.org/ for details.", VERSION);

  mainclock = time(0);

  printstatus(NULL);

  /* Create a tunnel interface */
  if (tun_new(&tun)) {
    log_err(0, "Failed to create tun");
    exit(1);
  }

  /*tun_setaddr(tun, &options.dhcplisten,  &options.net, &options.mask);*/
  tun_setaddr(tun, &options.dhcplisten,  &options.dhcplisten, &options.mask);
  tun_set_cb_ind(tun, cb_tun_ind);

  if (tun) tun_maxfd(tun, maxfd);
  if (options.ipup) tun_runscript(tun, options.ipup);

  
  /* Create an instance of dhcp */
  if (dhcp_new(&dhcp, APP_NUM_CONN, options.dhcpif,
	       options.dhcpusemac, options.dhcpmac, options.dhcpusemac, 
	       &options.dhcplisten, options.lease, 1, 
	       &options.uamlisten, options.uamport, 
	       options.eapolenable)) {
    log_err(0, "Failed to create dhcp");
    exit(1);
  }

  net_maxfd(&dhcp->ipif, maxfd);
  net_maxfd(&dhcp->arpif, maxfd);
  net_maxfd(&dhcp->eapif, maxfd);

  fd_max(dhcp->relayfd, maxfd);
  
  dhcp_set_cb_request(dhcp, cb_dhcp_request);
  dhcp_set_cb_connect(dhcp, cb_dhcp_connect);
  dhcp_set_cb_disconnect(dhcp, cb_dhcp_disconnect);
  dhcp_set_cb_data_ind(dhcp, cb_dhcp_data_ind);
  dhcp_set_cb_eap_ind(dhcp, cb_dhcp_eap_ind);
  dhcp_set_cb_getinfo(dhcp, cb_dhcp_getinfo);

  if (dhcp_set(dhcp, (options.debug & DEBUG_DHCP))) {
    log_err(0, "Failed to set DHCP parameters");
    exit(1);
  }

  fixup_options();

  /* Create an instance of radius */
  if (radius_new(&radius,
		 &options.radiuslisten, options.coaport, options.coanoipcheck,
		 &options.proxylisten, options.proxyport,
		 &options.proxyaddr, &options.proxymask,
		 options.proxysecret)) {
    log_err(0, "Failed to create radius");
    return -1;
  }

  if (radius->fd > maxfd)
    maxfd = radius->fd;
  
  if ((radius->proxyfd != -1) && (radius->proxyfd > maxfd))
    maxfd = radius->proxyfd;
  
  radius_set(radius, dhcp ? dhcp->ipif.hwaddr : 0, (options.debug & DEBUG_RADIUS));
  radius_set_cb_auth_conf(radius, cb_radius_auth_conf);
  radius_set_cb_coa_ind(radius, cb_radius_coa_ind);
  radius_set_cb_ind(radius, cb_radius_ind);

  if (options.acct_update)
    radius_set_cb_acct_conf(radius, cb_radius_acct_conf);

  /* Initialise connections */
  initconn();
  
  /* Allocate ippool for dynamic IP address allocation */
  if (ippool_new(&ippool, 
		 options.dynip, 
		 options.dhcpstart, 
		 options.dhcpend, 
		 options.statip, 
		 options.allowdyn, 
		 options.allowstat)) {
    log_err(0, "Failed to allocate IP pool!");
    exit(1);
  }

  /* Create an instance of redir */
  if (redir_new(&redir, &options.uamlisten, options.uamport, options.uamuiport)) {
    log_err(0, "Failed to create redir");
    return -1;
  }

  if (redir->fd[0] > maxfd) maxfd = redir->fd[0];
  if (redir->fd[1] > maxfd) maxfd = redir->fd[1];
  redir_set(redir, (options.debug));
  redir_set_cb_getstate(redir, cb_redir_getstate);

  memset(&admin_session, 0, sizeof(admin_session));
  memcpy(admin_session.ourmac, dhcp->ipif.hwaddr, sizeof(dhcp->ipif.hwaddr));
  acct_req(&admin_session, RADIUS_STATUS_TYPE_ACCOUNTING_ON);

  if (options.adminuser) {
    admin_session.is_adminsession = 1;
    strncpy(admin_session.s_state.redir.username, 
	    options.adminuser, sizeof(admin_session.s_state.redir.username));
    set_sessionid(&admin_session);
    chilliauth_radius(radius);
  }

  if (options.cmdsocket) {
    cmdsock = cmdsock_init();
    if (cmdsock > 0)
      maxfd = cmdsock;
  }

  /* Set up signal handlers */
  memset(&act, 0, sizeof(act));

  act.sa_handler = fireman;
  sigaction(SIGCHLD, &act, NULL);

  act.sa_handler = termination_handler;
  sigaction(SIGTERM, &act, NULL);
  sigaction(SIGINT, &act, NULL);

  act.sa_handler = sighup_handler;
  sigaction(SIGHUP, &act, NULL);

  /*
  act.sa_handler = alarm_handler;
  sigaction(SIGALRM, &act, NULL);

  memset(&itval, 0, sizeof(itval));
  itval.it_interval.tv_sec = 0;
  itval.it_interval.tv_usec = 500000; / * TODO 0.5 second * /
  itval.it_value.tv_sec = 0; 
  itval.it_value.tv_usec = 500000; / * TODO 0.5 second * /

  if (setitimer(ITIMER_REAL, &itval, NULL)) {
    log_err(errno, "setitimer() failed!");
  }
  */

  if (options.debug) 
    log_dbg("Waiting for client request...");


  /******************************************************************/
  /* Main select loop                                               */
  /******************************************************************/

  mainclock = time(0);
  while (keep_going) {

    if (do_sighup) {
      reprocess_options(argc, argv);
      fixup_options();

      do_sighup = 0;

      /* Reinit DHCP parameters */
      if (dhcp)
	dhcp_set(dhcp, (options.debug & DEBUG_DHCP));
      
      /* Reinit RADIUS parameters */
      radius_set(radius, dhcp ? dhcp->ipif.hwaddr : 0, (options.debug & DEBUG_RADIUS));
      
      /* Reinit Redir parameters */
      redir_set(redir, options.debug);

      if (options.adminuser)
	chilliauth_radius(radius);
    }

    if (lastSecond != (thisSecond = mainclock) /*do_timeouts*/) {
      radius_timeout(radius);

      if (dhcp) 
	dhcp_timeout(dhcp);
      
      checkconn();
      lastSecond = thisSecond;
      /*do_timeouts = 0;*/
    }

    fd_zero(&fds);

    if (tun) tun_fdset(tun, &fds);
    if (dhcp) {
      net_fdset(&dhcp->ipif, &fds);
#if defined(__linux__)
      net_fdset(&dhcp->arpif, &fds);
      net_fdset(&dhcp->eapif, &fds);
      fd_set(dhcp->relayfd, &fds);
#endif
    }

    fd_set(radius->fd, &fds);
    fd_set(radius->proxyfd, &fds);
    fd_set(redir->fd[0], &fds);
    fd_set(redir->fd[1], &fds);
    fd_set(cmdsock, &fds);

    idleTime.tv_sec = 0; /*IDLETIME;*/
    idleTime.tv_usec = 500;
    /*radius_timeleft(radius, &idleTime);
      if (dhcp) dhcp_timeleft(dhcp, &idleTime);*/
    switch (status = select(maxfd + 1, &fds, NULL, NULL, &idleTime /* NULL */)) {
    case -1:
      if (EINTR != errno) {
	log_err(errno, "select() returned -1!");
      }
      break;
    case 0:
    default:
      break;
    }

    mainclock = time(0);

    if ((msgresult = 
	 TEMP_FAILURE_RETRY(msgrcv(redir->msgid, (struct msgbuf *)&msg, 
				   sizeof(msg.mdata), 0, IPC_NOWAIT)))  == -1) {
      if ((errno != EAGAIN) && (errno != ENOMSG))
	log_err(errno, "msgrcv() failed!");
    }

    if (msgresult > 0) 
      uam_msg(&msg);
    
    if (status > 0) {

      if (tun) tun_ckset(tun, &fds);
     
      if (dhcp) {

	if (fd_isset(dhcp->relayfd, &fds) && dhcp_relay_decaps(dhcp) < 0)
	  log_err(0, "dhcp_relay_decaps() failed!");
      
#if defined(__linux__)

	if (net_isset(&dhcp->ipif, &fds) && dhcp_decaps(dhcp) < 0)
	  log_err(0, "dhcp_decaps() failed!");
      
	if (net_isset(&dhcp->arpif, &fds) && dhcp_arp_ind(dhcp) < 0)
	  log_err(0, "dhcp_arpind() failed!");
	
	if (net_isset(&dhcp->eapif, &fds) && dhcp_eapol_ind(dhcp) < 0)
	  log_err(0, "dhcp_eapol_ind() failed!");

#elif defined (__FreeBSD__)  || defined (__APPLE__) || defined (__OpenBSD__)

	if (net_isset(&dhcp->ipif, &fds) && dhcp_decaps(dhcp) < 0)
	  log_err(0, "dhcp_decaps() failed!");

#endif

      }

      if (fd_isset(radius->fd, &fds) && radius_decaps(radius) < 0)
	log_err(0, "radius_ind() failed!");

      if (fd_isset(radius->proxyfd, &fds) && radius_proxy_ind(radius) < 0)
	log_err(0, "radius_proxy_ind() failed!");

      if (fd_isset(redir->fd[0], &fds) && redir_accept(redir, 0) < 0)
	log_err(0, "redir_accept() failed!");

      if (fd_isset(redir->fd[1], &fds) && redir_accept(redir, 1) < 0)
	log_err(0, "redir_accept() failed!");
      
      if (fd_isset(cmdsock, &fds) && cmdsock_accept(cmdsock) < 0)
	log_err(0, "cmdsock_accept() failed!");

    }
  }
  
  if (options.debug) 
    log_dbg("Terminating ChilliSpot!");

  killconn();

  if (redir) 
    redir_free(redir);

  if (radius) 
    radius_free(radius);

  if (dhcp) 
    dhcp_free(dhcp);

  if (tun && options.ipdown)
    tun_runscript(tun, options.ipdown);

  if (tun) 
    tun_free(tun);

  if (ippool) 
    ippool_free(ippool);

  return 0;
  
}
