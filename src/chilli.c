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

struct timeval checktime;
struct timeval rereadtime;

static int keep_going = 1;
/*static int do_timeouts = 1;*/
static int do_sighup = 0;

/* Forward declarations */
static int acct_req(struct app_conn_t *conn, int status_type);

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
  struct timeval timenow;
  gettimeofday(&timenow, NULL);
  snprintf(appconn->sessionid, sizeof(appconn->sessionid), "%.8x%.8x",
	   (int) timenow.tv_sec, appconn->unit);
  appconn->classlen = 0;
}

/* Used to write process ID to file. Assume someone else will delete */
void static log_pid(char *pidfile) {
  FILE *file;
  mode_t oldmask;

  oldmask = umask(022);
  file = fopen(pidfile, "w");
  umask(oldmask);
  if(!file)
    return;
  fprintf(file, "%d\n", getpid());
  (void) fclose(file);
}

#ifdef LEAKY_BUCKET
/* Perform leaky bucket on up- and downlink traffic */
int static leaky_bucket(struct app_conn_t *conn, int octetsup, int octetsdown) {
  
  struct timeval timenow;
  uint64_t timediff; /* In microseconds */
  int result = 0;

 
  gettimeofday(&timenow, NULL);

  timediff = (timenow.tv_sec - conn->last_time.tv_sec) * ((uint64_t) 1000000);
  timediff += (timenow.tv_usec - conn->last_time.tv_usec);

  /*  if (options.debug) log_dbg("Leaky bucket timediff: %lld, bucketup: %d, bucketdown: %d %d %d\n", 
			    timediff, conn->bucketup, conn->bucketdown, 
			    octetsup, octetsdown);*/

  if (conn->params.bandwidthmaxup) {

    /* Subtract what the leak since last time we visited */
    if (conn->bucketup > ((timediff * conn->params.bandwidthmaxup)/8000000)) {
      conn->bucketup -= (timediff * conn->params.bandwidthmaxup) / 8000000;
    }
    else {
      conn->bucketup = 0;
    }
    
    if ((conn->bucketup + octetsup) > conn->bucketupsize) {
      /*if (options.debug) log_dbg("Leaky bucket deleting uplink packet\n");*/
      result = -1;
    }
    else {
      conn->bucketup += octetsup;
    }
  }

  if (conn->params.bandwidthmaxdown) {
    if (conn->bucketdown > ((timediff * conn->params.bandwidthmaxdown)/8000000)) {
      conn->bucketdown -= (timediff * conn->params.bandwidthmaxdown) / 8000000;
    }
    else {
      conn->bucketdown = 0;
    }
    
    if ((conn->bucketdown + octetsdown) > conn->bucketdownsize) {
      /*if (options.debug) log_dbg("Leaky bucket deleting downlink packet\n");*/
      result = -1;
    }
    else {
      conn->bucketdown += octetsdown;
    }
  }

  gettimeofday(&conn->last_time, NULL);
    
  return result;
}
#endif


/* Run external script */
#define VAL_STRING   0
#define VAL_IN_ADDR  1
#define VAL_MAC_ADDR 2
#define VAL_ULONG    3
#define VAL_USHORT   4

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
    snprintf(s, sizeof(s)-1, "%ld", *(unsigned long *)value);
    v = s;
    break;

  case VAL_USHORT:
    snprintf(s, sizeof(s)-1, "%d", (int)(*(unsigned short *)value));
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

  set_env("DEV", VAL_STRING, tun->devname, 0);
  set_env("NET", VAL_IN_ADDR, &appconn->net, 0);
  set_env("MASK", VAL_IN_ADDR, &appconn->mask, 0);
  set_env("ADDR", VAL_IN_ADDR, &appconn->ourip, 0);
  set_env("USER_NAME", VAL_STRING, appconn->proxyuser, 0);
  set_env("NAS_IP_ADDRESS", VAL_IN_ADDR,&options.radiuslisten, 0);
  set_env("SERVICE_TYPE", VAL_STRING, "1", 0);
  set_env("FRAMED_IP_ADDRESS", VAL_IN_ADDR, &appconn->hisip, 0);
  set_env("FILTER_ID", VAL_STRING, appconn->params.filteridbuf, 0);
  set_env("STATE", VAL_STRING, appconn->statebuf, appconn->statelen);
  set_env("CLASS", VAL_STRING, appconn->classbuf, appconn->classlen);
  set_env("SESSION_TIMEOUT", VAL_ULONG, &appconn->params.sessiontimeout, 0);
  set_env("IDLE_TIMEOUT", VAL_USHORT, &appconn->params.idletimeout, 0);
  set_env("CALLING_STATION_ID", VAL_MAC_ADDR, appconn->hismac, 0);
  set_env("CALLED_STATION_ID", VAL_MAC_ADDR, appconn->ourmac, 0);
  set_env("NAS_ID", VAL_STRING, options.radiusnasid, 0);
  set_env("NAS_PORT_TYPE", VAL_STRING, "19", 0);
  set_env("ACCT_SESSION_ID", VAL_STRING, appconn->sessionid, 0);
  set_env("ACCT_INTERIM_INTERVAL", VAL_USHORT, &appconn->params.interim_interval, 0);
  set_env("WISPR_LOCATION_ID", VAL_STRING, options.radiuslocationid, 0);
  set_env("WISPR_LOCATION_NAME", VAL_STRING, options.radiuslocationname, 0);
  set_env("WISPR_BANDWIDTH_MAX_UP", VAL_ULONG, &appconn->params.bandwidthmaxup, 0);
  set_env("WISPR_BANDWIDTH_MAX_DOWN", VAL_ULONG, &appconn->params.bandwidthmaxdown, 0);
  /*set_env("WISPR-SESSION_TERMINATE_TIME", VAL_USHORT, &appconn->sessionterminatetime, 0);*/
  set_env("CHILLISPOT_MAX_INPUT_OCTETS", VAL_ULONG, &appconn->params.maxinputoctets, 0);
  set_env("CHILLISPOT_MAX_OUTPUT_OCTETS", VAL_ULONG, &appconn->params.maxoutputoctets, 0);
  set_env("CHILLISPOT_MAX_TOTAL_OCTETS", VAL_ULONG, &appconn->params.maxtotaloctets, 0);

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
  gettimeofday(&checktime, NULL);
  gettimeofday(&rereadtime, NULL);
  return 0;
}

int static newconn(struct app_conn_t **conn)
{
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
  }
  else {
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

int static freeconn(struct app_conn_t *conn)
{
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
  memset(conn, 0, sizeof(*conn));
  
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

int static getconn(struct app_conn_t **conn, uint32_t nasip, uint32_t nasport) 
{
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
  appconn->authenticated = 0;
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
  uint32_t sessiontime;
  uint32_t idletime;
  uint32_t interimtime;
  struct timeval timenow;
  gettimeofday(&timenow, NULL);

  sessiontime = timenow.tv_sec - conn->start_time.tv_sec;
  sessiontime += (timenow.tv_usec - conn->start_time.tv_usec) / 1000000;
  idletime = timenow.tv_sec - conn->last_time.tv_sec;
  idletime += (timenow.tv_usec - conn->last_time.tv_usec) / 1000000;
  interimtime = timenow.tv_sec - conn->interim_time.tv_sec;
  interimtime += (timenow.tv_usec - conn->interim_time.tv_usec) / 1000000;
  
  if ((conn->params.sessiontimeout) &&
      (sessiontime > conn->params.sessiontimeout)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->params.sessionterminatetime) && 
	   (timenow.tv_sec > conn->params.sessionterminatetime)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->params.idletimeout) && 
	   (idletime > conn->params.idletimeout)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_IDLE_TIMEOUT);
  }
  else if ((conn->params.maxinputoctets) &&
	   (conn->input_octets > conn->params.maxinputoctets)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->params.maxoutputoctets) &&
	   (conn->output_octets > conn->params.maxoutputoctets)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->params.maxtotaloctets) &&
	   ((conn->input_octets + conn->output_octets) > 
	    conn->params.maxtotaloctets)) {
    terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_SESSION_TIMEOUT);
  }
  else if ((conn->params.interim_interval) &&
	   (interimtime > conn->params.interim_interval)) {
    acct_req(conn, RADIUS_STATUS_TYPE_INTERIM_UPDATE);
  }
}

int static checkconn()
{
  struct app_conn_t *conn;
  struct dhcp_conn_t* dhcpconn;
  uint32_t checkdiff;
  uint32_t rereaddiff;
  struct timeval timenow;
  gettimeofday(&timenow, NULL);

  checkdiff = timenow.tv_sec - checktime.tv_sec;
  checkdiff += (timenow.tv_usec - checktime.tv_usec) / 1000000;

  if (checkdiff < CHECK_INTERVAL)
    return 0;

  checktime = timenow;
  
  if (admin_session.authenticated) {
    session_interval(&admin_session);
  }

  for (conn = firstusedconn; conn; conn=conn->next) {
    if ((conn->inuse != 0) && (conn->authenticated == 1)) {
      if (!(dhcpconn = (struct dhcp_conn_t*) conn->dnlink)) {
	log_err(0, "No downlink protocol");
	return -1;
      }
      session_interval(conn);
    }
  }
  
  /* Reread configuration file and recheck DNS */
  if (options.interval) {
    rereaddiff = timenow.tv_sec - rereadtime.tv_sec;
    rereaddiff += (timenow.tv_usec - rereadtime.tv_usec) / 1000000;
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
    if ((conn->inuse != 0) && (conn->authenticated == 1)) {
      if (!(dhcpconn = (struct dhcp_conn_t*) conn->dnlink)) {
	log_err(0, "No downlink protocol");
	return -1;
      }
      terminate_appconn(conn, RADIUS_TERMINATE_CAUSE_NAS_REBOOT);
    }
  }

  if (admin_session.authenticated) {
    admin_session.terminate_cause = RADIUS_TERMINATE_CAUSE_NAS_REBOOT;
    acct_req(&admin_session, RADIUS_STATUS_TYPE_STOP);
  }

  acct_req(&admin_session, RADIUS_STATUS_TYPE_ACCOUNTING_OFF);

  return 0;
}

/* Compare a MAC address to the addresses given in the macallowed option */
int static maccmp(unsigned char *mac) {
  int i;
  for (i=0; i<options.macoklen; i++) {
    if (!memcmp(mac, options.macok[i], DHCP_ETH_ALEN)) {
      return 0;
    }
  }
  return -1;
}

int static macauth_radius(struct app_conn_t *appconn) {
  struct radius_packet_t radius_pack;
  struct dhcp_conn_t* dhcpconn = (struct dhcp_conn_t*) appconn->dnlink;
  char mac[MACSTRLEN+1];

  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REQUEST)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }
  
  /* Include his MAC address */
  snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	   dhcpconn->hismac[0], dhcpconn->hismac[1],
	   dhcpconn->hismac[2], dhcpconn->hismac[3],
	   dhcpconn->hismac[4], dhcpconn->hismac[5]);

  strncpy(appconn->proxyuser, mac, USERNAMESIZE);
  appconn->proxyuser[USERNAMESIZE-1] = 0;
  if (options.macsuffix) {
    strncat(appconn->proxyuser, options.macsuffix, USERNAMESIZE);
    appconn->proxyuser[USERNAMESIZE-1] = 0;
  }
  appconn->proxyuserlen = strlen(appconn->proxyuser);

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
			(uint8_t*) appconn->proxyuser, appconn->proxyuserlen);

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
			(uint8_t*) (options.macpasswd ? options.macpasswd : appconn->proxyuser), 
			options.macpasswd ? strlen(options.macpasswd) : appconn->proxyuserlen);
  
  appconn->authtype = PAP_PASSWORD;

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0,
		 (uint8_t*) mac, MACSTRLEN);
  
  if (options.nasmac) {
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
		   (uint8_t *)options.nasmac, strlen(options.nasmac)); 
  } else {
    /* Include our MAC address */
    (void) snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
		    dhcpconn->ourmac[0], dhcpconn->ourmac[1],
		    dhcpconn->ourmac[2], dhcpconn->ourmac[3],
		    dhcpconn->ourmac[4], dhcpconn->ourmac[5]);
    
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
			  (uint8_t*) mac, MACSTRLEN);
  }
  
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		 appconn->unit, NULL, 0);

  radius_addnasip(radius, &radius_pack);

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_SERVICE_TYPE, 0, 0,
		 RADIUS_SERVICE_TYPE_LOGIN, NULL, 0); /* WISPr_V1.0 */
  
  /* Include NAS-Identifier if given in configuration options */
  if (options.radiusnasid)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
		   (uint8_t*) options.radiusnasid, strlen(options.radiusnasid));

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0,
		 (uint8_t*) appconn->sessionid, REDIR_SESSIONID_LEN-1);

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
			options.radiusnasporttype, NULL, 0);

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		 0, 0, 0, NULL, RADIUS_MD5LEN);

  if (options.radiuslocationid)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_ID, 0,
		   (uint8_t*) options.radiuslocationid, 
		   strlen(options.radiuslocationid));

  if (options.radiuslocationname)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_NAME, 0,
		   (uint8_t*) options.radiuslocationname, 
		   strlen(options.radiuslocationname));
  
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
  (void) radius_resp(radius, &radius_pack, &conn->radiuspeer, conn->authenticator);
  return 0;
}

/* Reply with an access challenge */
int static radius_access_challenge(struct app_conn_t *conn) {
  struct radius_packet_t radius_pack;
  int offset = 0;
  int eaplen = 0;
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
  
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		 0, 0, 0, NULL, RADIUS_MD5LEN);
  
  if (conn->statelen) {
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_STATE, 0, 0, 0,
		   conn->statebuf,
		   conn->statelen);
  }
  
  (void) radius_resp(radius, &radius_pack, &conn->radiuspeer, conn->authenticator);

  return 0;
}

/* Send off an access accept */

int static radius_access_accept(struct app_conn_t *conn) {
  struct radius_packet_t radius_pack;
  int offset = 0;
  int eaplen = 0;
  uint8_t mppekey[RADIUS_ATTR_VLEN];
  int mppelen;

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
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_EAP_MESSAGE, 0, 0, 0,
		   conn->chal + offset, eaplen);
    offset += eaplen;
  }

  /* Message Authenticator */
  if (conn->challen)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		   0, 0, 0, NULL, RADIUS_MD5LEN);

  if (conn->sendkey) {
    radius_keyencode(radius, mppekey, RADIUS_ATTR_VLEN,
		     &mppelen, conn->sendkey,
		     conn->sendlen, conn->authenticator,
		     radius->proxysecret, radius->proxysecretlen);

    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_MS, RADIUS_ATTR_MS_MPPE_SEND_KEY, 0,
		   mppekey, mppelen);
  }

  if (conn->recvkey) {
    radius_keyencode(radius, mppekey, RADIUS_ATTR_VLEN,
		     &mppelen, conn->recvkey,
		     conn->recvlen, conn->authenticator,
		     radius->proxysecret, radius->proxysecretlen);
    
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_MS, RADIUS_ATTR_MS_MPPE_RECV_KEY, 0,
		   mppekey, mppelen);
  }
  
  (void) radius_resp(radius, &radius_pack, &conn->radiuspeer, conn->authenticator);
  return 0;
}


/*********************************************************
 *
 * radius accounting functions
 * Used to send accounting request to radius server
 *
 *********************************************************/

int static acct_req(struct app_conn_t *conn, int status_type)
{
  struct radius_packet_t radius_pack;
  char mac[MACSTRLEN+1];
  char portid[16+1];
  struct timeval timenow;
  uint32_t timediff;

  if (RADIUS_STATUS_TYPE_START == status_type) {
    gettimeofday(&conn->start_time, NULL);
    conn->interim_time = conn->start_time;
    conn->last_time = conn->start_time;
    conn->input_packets = 0;
    conn->output_packets = 0;
    conn->input_octets = 0;
    conn->output_octets = 0;
  }

  if (RADIUS_STATUS_TYPE_INTERIM_UPDATE == status_type) {
    gettimeofday(&conn->interim_time, NULL);
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
		   (uint8_t*) conn->user, conn->userlen);
    
    if (conn->classlen) {
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_CLASS, 0, 0, 0,
		     conn->classbuf,
		     conn->classlen);
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
      
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_FRAMED_IP_ADDRESS, 0, 0,
		     ntohl(conn->hisip.s_addr), NULL, 0);
      
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		     conn->unit, NULL, 0);
      snprintf(portid, 16+1, "%.8d", conn->unit);
      radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_ID, 0, 0, 0,
		     (uint8_t*) portid, strlen(portid));
    }
    
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0,
		   (uint8_t*) conn->sessionid, REDIR_SESSIONID_LEN-1);
    
  }

  radius_addnasip(radius, &radius_pack);

  if (options.nasmac) {
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
		   (uint8_t *)options.nasmac, strlen(options.nasmac)); 
  } else {
    snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	     conn->ourmac[0], conn->ourmac[1],
	     conn->ourmac[2], conn->ourmac[3],
	     conn->ourmac[4], conn->ourmac[5]);
    
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
		   (uint8_t*) mac, MACSTRLEN);
  }

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
		   (uint32_t) conn->input_octets, NULL, 0);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_OUTPUT_OCTETS, 0, 0,
		   (uint32_t) conn->output_octets, NULL, 0);

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_INPUT_GIGAWORDS, 
		   0, 0, (uint32_t) (conn->input_octets >> 32), NULL, 0);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_OUTPUT_GIGAWORDS, 
		   0, 0, (uint32_t) (conn->output_octets >> 32), NULL, 0);

    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_INPUT_PACKETS, 0, 0,
		   conn->input_packets, NULL, 0);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_OUTPUT_PACKETS, 0, 0,
		   conn->output_packets, NULL, 0);

    gettimeofday(&timenow, NULL);
    timediff = timenow.tv_sec - conn->start_time.tv_sec;
    timediff += (timenow.tv_usec - conn->start_time.tv_usec) / 1000000;
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_SESSION_TIME, 0, 0,
		   timediff, NULL, 0);  
  }

  if (options.radiuslocationid)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_ID, 0,
		   (uint8_t*) options.radiuslocationid,
		   strlen(options.radiuslocationid));

  if (options.radiuslocationname)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_NAME, 0,
		   (uint8_t*) options.radiuslocationname, 
		   strlen(options.radiuslocationname));


  if (status_type == RADIUS_STATUS_TYPE_STOP ||
      status_type == RADIUS_STATUS_TYPE_ACCOUNTING_OFF) {

    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_TERMINATE_CAUSE, 
		   0, 0, conn->terminate_cause, NULL, 0);

    if (status_type == RADIUS_STATUS_TYPE_STOP) {
      /* TODO: This probably belongs somewhere else */
      if (options.condown) {
	if (options.debug)
	  log_dbg("Calling connection down script: %s\n",options.condown);
	(void) runscript(conn, options.condown);
      }
    }
  }
  
  (void) radius_req(radius, &radius_pack, conn);
  
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
  struct ippoolm_t *ipm;

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
    if (!(dhcpconn = (struct dhcp_conn_t*) appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }
    
    /* Allocate dynamic IP address */
    /*XXX    if (ippool_newip(ippool, &ipm, &appconn->reqip, 0)) {*/
    if (newip(&ipm, &appconn->reqip)) {
      log_err(0, "Failed allocate dynamic IP address");
      return 0;
    }

    appconn->hisip.s_addr = ipm->addr.s_addr;
    
    /* TODO: Listening address is network address plus 1 */
    appconn->ourip.s_addr = htonl((ntohl(options.net.s_addr)+1));
    
    appconn->uplink =  ipm;
    ipm->peer = appconn;
    
    dhcp_set_addrs(dhcpconn, &ipm->addr, &options.mask, &appconn->ourip,
		   &options.dns1, &options.dns2, options.domain);
    
    dhcpconn->authstate = DHCP_AUTH_DNAT;
    appconn->dnprot = DNPROT_UAM;
    
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
    if (!(dhcpconn = (struct dhcp_conn_t*) appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    dhcp_sendEAP(dhcpconn, appconn->chal, appconn->challen);
    break;

  case DNPROT_UAM:

  case DNPROT_WPA:
    radius_access_challenge(appconn);
    break;

  case DNPROT_MAC:
    break;

  default:
    log_err(0, "Unknown downlink protocol");
  }

  return 0;
}

int static dnprot_accept(struct app_conn_t *appconn) {
  struct dhcp_conn_t* dhcpconn = NULL;

  if (!appconn->hisip.s_addr) {
    log_err(0, "IP address not allocated");
    return 0;
  }

  switch (appconn->dnprot) {
  case DNPROT_EAPOL:
    if (!(dhcpconn = (struct dhcp_conn_t*) appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    (void) dhcp_set_addrs(dhcpconn, &appconn->hisip, &appconn->mask,
			  &appconn->ourip, &appconn->dns1, &appconn->dns2,
			  options.domain);
    
    /* This is the one and only place eapol authentication is accepted */
    dhcpconn->authstate = DHCP_AUTH_PASS;

    /* Initialise parameters for accounting */
    appconn->userlen = appconn->proxyuserlen; 
    memcpy(appconn->user, appconn->proxyuser, appconn->userlen);
    appconn->nasip = appconn->proxynasip; 
    appconn->nasport = appconn->proxynasport; 
    memcpy(appconn->hismac, appconn->proxyhismac, DHCP_ETH_ALEN);
    memcpy(appconn->ourmac, appconn->proxyourmac, DHCP_ETH_ALEN);

    /* Tell client it was successful */
    (void) dhcp_sendEAP(dhcpconn, appconn->chal, appconn->challen);

    sys_err(LOG_WARNING, __FILE__, __LINE__, 0, 
	    "Do not know how to set encryption keys on this platform!");
    break;

  case DNPROT_UAM:
    if (!(dhcpconn = (struct dhcp_conn_t*) appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    (void) dhcp_set_addrs(dhcpconn, &appconn->hisip, &appconn->mask, 
			  &appconn->ourip, &appconn->dns1, &appconn->dns2,
			  options.domain);
    
    /* This is the one and only place UAM authentication is accepted */
    dhcpconn->authstate = DHCP_AUTH_PASS;
    appconn->params.require_uam_auth = 0;

    /* Initialise parameters for accounting */
    appconn->userlen = appconn->proxyuserlen; 
    memcpy(appconn->user, appconn->proxyuser, appconn->userlen);
    appconn->nasip = appconn->proxynasip; 
    appconn->nasport = appconn->proxynasport; 
    memcpy(appconn->hismac, appconn->proxyhismac, DHCP_ETH_ALEN);
    memcpy(appconn->ourmac, appconn->proxyourmac, DHCP_ETH_ALEN);
    break;

  case DNPROT_WPA:
    if (!(dhcpconn = (struct dhcp_conn_t*) appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }

    (void) dhcp_set_addrs(dhcpconn, &appconn->hisip, &appconn->mask, 
			  &appconn->ourip, &appconn->dns1, &appconn->dns2,
			  options.domain);
    
    /* This is the one and only place WPA authentication is accepted */
    if (appconn->params.require_uam_auth) {
      appconn->dnprot = DNPROT_DHCP_NONE;
      dhcpconn->authstate = DHCP_AUTH_NONE;
    }
    else {
      dhcpconn->authstate = DHCP_AUTH_PASS;
    }
    

    /* Initialise parameters for accounting */
    appconn->userlen = appconn->proxyuserlen; 
    memcpy(appconn->user, appconn->proxyuser, appconn->userlen);
    appconn->nasip = appconn->proxynasip; 
    appconn->nasport = appconn->proxynasport; 
    memcpy(appconn->hismac, appconn->proxyhismac, DHCP_ETH_ALEN);
    memcpy(appconn->ourmac, appconn->proxyourmac, DHCP_ETH_ALEN);

    /* Tell access point it was successful */
    radius_access_accept(appconn);

    break;

  case DNPROT_MAC:
    if (!(dhcpconn = (struct dhcp_conn_t*) appconn->dnlink)) {
      log_err(0, "No downlink protocol");
      return 0;
    }
    
    (void) dhcp_set_addrs(dhcpconn, &appconn->hisip, &appconn->mask, 
			  &appconn->ourip, &appconn->dns1, &appconn->dns2,
			  options.domain);
    
    /* This is the one and only place MAC authentication is accepted */
    dhcpconn->authstate = DHCP_AUTH_PASS;
    appconn->params.require_uam_auth = 0;
    
    /* Initialise parameters for accounting */
    appconn->userlen = appconn->proxyuserlen; 
    memcpy(appconn->user, appconn->proxyuser, appconn->userlen);
    appconn->nasip = appconn->proxynasip; 
    appconn->nasport = appconn->proxynasport; 
    memcpy(appconn->hismac, appconn->proxyhismac, DHCP_ETH_ALEN);
    memcpy(appconn->ourmac, appconn->proxyourmac, DHCP_ETH_ALEN);

    break;

  default:
    log_err(0, "Unknown downlink protocol");
    return 0;
  }

  if (!appconn->params.require_uam_auth) {
    /* This is the one and only place state is switched to authenticated */
    appconn->authenticated = 1;
    
    /* Run connection up script */
    if (options.conup) {
      if (options.debug) log_dbg("Calling connection up script: %s\n", options.conup);
      runscript(appconn, options.conup);
    }
    
    printstatus(appconn);
    
    acct_req(appconn, RADIUS_STATUS_TYPE_START);
  }
  
  return 0;
}


/*********************************************************
 *
 * Tun callbacks
 *
 * Called from the tun_decaps function. This method is passed either
 * a TAP Ethernet frame or a TUN IP packet. 
 */


int cb_tun_ind(struct tun_t *tun, void *pack, unsigned len) {
  struct in_addr dst;
  struct ippoolm_t *ipm;
  struct app_conn_t *appconn;
  struct tun_packet_t *iph;

  if (options.tap) {
    struct dhcp_ethhdr_t *ethh = (struct dhcp_ethhdr_t *)pack;
    iph = (struct tun_packet_t*)(pack + DHCP_ETH_HLEN);

    switch (ntohs(ethh->prot)) {

    case DHCP_ETH_IP:
      break;

    case DHCP_ETH_ARP:
      log_dbg("arp: dst=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x src=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x prot=%.4x\n",
	      ethh->dst[0],ethh->dst[1],ethh->dst[2],ethh->dst[3],ethh->dst[4],ethh->dst[5],
	      ethh->src[0],ethh->src[1],ethh->src[2],ethh->src[3],ethh->src[4],ethh->src[5],
	      ntohs(ethh->prot));
      /*
       * send arp reply with us being target
       */
      {
	struct dhcp_arp_fullpacket_t *p = (struct dhcp_arp_fullpacket_t *)pack;
	struct dhcp_arp_fullpacket_t packet;
	uint16_t length = sizeof(packet);
	struct in_addr reqaddr;

	/* Get local copy */
	memcpy(&reqaddr.s_addr, p->arp.tpa, DHCP_IP_ALEN);

	if (ippool_getip(ippool, &ipm, &reqaddr)) {
	  if (options.debug) 
	    log_dbg("ARP for unknown IP %s\n", inet_ntoa(reqaddr));
	  return 0;
	}
	
	if (!((ipm->peer) || ((struct app_conn_t*) ipm->peer)->dnlink)) {
	  log_err(0, "No peer protocol defined for ARP request");
	  return 0;
	}
	
	appconn = (struct app_conn_t*) ipm->peer;
	
	/* Get packet default values */
	memset(&packet, 0, sizeof(packet));
	
	/* ARP Payload */
	packet.arp.hrd = htons(DHCP_HTYPE_ETH);
	packet.arp.pro = htons(DHCP_ETH_IP);
	packet.arp.hln = DHCP_ETH_ALEN;
	packet.arp.pln = DHCP_IP_ALEN;
	packet.arp.op  = htons(DHCP_ARP_REPLY);
	
	/* Source address */
	/*memcpy(packet.arp.sha, dhcp->arp_hwaddr, DHCP_ETH_ALEN);
	  memcpy(packet.arp.spa, &dhcp->ourip.s_addr, DHCP_IP_ALEN);*/
	/*memcpy(packet.arp.sha, appconn->hismac, DHCP_ETH_ALEN);*/
	memcpy(packet.arp.sha, options.tapmac, DHCP_ETH_ALEN);
	memcpy(packet.arp.spa, &appconn->hisip.s_addr, DHCP_IP_ALEN);
	
	/* Target address */
	/*memcpy(packet.arp.tha, &appconn->hismac, DHCP_ETH_ALEN);
	  memcpy(packet.arp.tpa, &appconn->hisip.s_addr, DHCP_IP_ALEN); */
	memcpy(packet.arp.tha, p->arp.sha, DHCP_ETH_ALEN);
	memcpy(packet.arp.tpa, p->arp.spa, DHCP_IP_ALEN);
	
	/* Ethernet header */
	memcpy(packet.ethh.dst, p->ethh.src, DHCP_ETH_ALEN);
	memcpy(packet.ethh.src, dhcp->hwaddr, DHCP_ETH_ALEN);
	packet.ethh.prot = htons(DHCP_ETH_ARP);
	
	return tun_encaps(tun, &packet, length);
      }
    }
  } else {
    iph = (struct tun_packet_t*)pack;
  }

  /*  if (options.debug) 
      log_dbg("cb_tun_ind. Packet received: Forwarding to link layer\n");*/

  dst.s_addr = iph->dst;

  if (ippool_getip(ippool, &ipm, &dst)) {
    if (options.debug) 
      log_dbg("Received packet with no destination! %s", inet_ntoa(dst));
    return 0;
  }

  if (!((ipm->peer) || ((struct app_conn_t*) ipm->peer)->dnlink)) {
    log_err(0, "No peer protocol defined");
    return 0;
  }

  appconn = (struct app_conn_t*) ipm->peer;

  /* If the ip src is uamlisten and psrc is uamport we won't call leaky_bucket */
  if ( ! (iph->src  == options.uamlisten.s_addr && 
	  iph->psrc == htons(options.uamport))) {
    if (appconn->authenticated == 1) {

#ifndef LEAKY_BUCKET
    gettimeofday(&appconn->last_time, NULL);
#endif

#ifdef LEAKY_BUCKET
#ifndef COUNT_DOWNLINK_DROP
    if (leaky_bucket(appconn, 0, len)) return 0;
#endif
#endif
    if (options.swapoctets) {
      appconn->output_packets++;
      appconn->output_octets += len;
      if (admin_session.authenticated) {
	admin_session.output_packets++;
	admin_session.output_octets+=len;
      }
    } else {
      appconn->input_packets++;
      appconn->input_octets += len;
      if (admin_session.authenticated) {
	admin_session.input_packets++;
	admin_session.input_octets+=len;
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
  case DNPROT_UAM:
  case DNPROT_WPA:
  case DNPROT_MAC:
    (void) dhcp_data_req((struct dhcp_conn_t *) appconn->dnlink, pack, len);
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
  
  if (!((ipm->peer) || ((struct app_conn_t*) ipm->peer)->dnlink)) {
    log_err(0, "No peer protocol defined");
    return -1;
  }
  
  appconn = (struct app_conn_t*) ipm->peer;
  dhcpconn = (struct dhcp_conn_t*) appconn->dnlink;
  
  conn->authenticated = appconn->authenticated;
  memcpy(conn->uamchal, appconn->uamchal, REDIR_MD5LEN);
  conn->uamtime = appconn->uamtime;
  conn->nasip = options.radiuslisten;
  conn->nasport = appconn->unit;
  memcpy(conn->hismac, dhcpconn->hismac, DHCP_ETH_ALEN);
  memcpy(conn->ourmac, dhcpconn->ourmac, DHCP_ETH_ALEN);
  memcpy(conn->sessionid, appconn->sessionid, REDIR_SESSIONID_LEN);
  memcpy(conn->classbuf, appconn->classbuf, sizeof(conn->classbuf));
  conn->classlen = appconn->classlen;
  conn->ourip = appconn->ourip;
  conn->hisip = appconn->hisip;

  memcpy(&conn->params, &appconn->params, sizeof(appconn->params));

  if (appconn->uamexit || 
      ((!conn->userurl || !*conn->userurl) && 
       (appconn->userurl && *appconn->userurl))) 
  {
    strncpy(conn->userurl, appconn->userurl, REDIR_MAXCHAR);
    conn->userurl[REDIR_MAXCHAR-1] = 0;
  }   

  /* reset state */
  appconn->uamexit=0;

  /* Stuff needed for status */
  conn->input_octets    = appconn->input_octets;
  conn->output_octets   = appconn->output_octets;
  conn->start_time      = appconn->start_time;
  conn->last_time       = appconn->last_time;
 
  if (appconn->authenticated == 1)
    return 1;
  else 
    return 0;
}


/*********************************************************
 *
 * Functions supporting radius callbacks
 *
 *********************************************************/

/* Handle an accounting request */
int accounting_request(struct radius_packet_t *pack,
		       struct sockaddr_in *peer) {
  int n;
  struct radius_attr_t *hismacattr = NULL;
  struct radius_attr_t *typeattr = NULL;
  struct radius_attr_t *nasipattr = NULL;
  struct radius_attr_t *nasportattr = NULL;
  struct radius_packet_t radius_pack;
  struct app_conn_t *appconn = NULL;
  struct dhcp_conn_t *dhcpconn = NULL;
  uint8_t hismac[DHCP_ETH_ALEN];
  char macstr[RADIUS_ATTR_VLEN];
  int macstrlen;
  unsigned int temp[DHCP_ETH_ALEN];
  int	i;
  uint32_t nasip = 0;
  uint32_t nasport = 0;


  if (radius_default_pack(radius, &radius_pack, 
			  RADIUS_CODE_ACCOUNTING_RESPONSE)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }
  radius_pack.id = pack->id;
  
  /* Status type */
  if (radius_getattr(pack, &typeattr, RADIUS_ATTR_ACCT_STATUS_TYPE, 0, 0, 0)) {
    log_err(0, "Status type is missing from radius request");
    (void) radius_resp(radius, &radius_pack, peer, pack->authenticator);
    return 0;
  }

  if (typeattr->v.i != htonl(RADIUS_STATUS_TYPE_STOP)) {
    (void) radius_resp(radius, &radius_pack, peer, pack->authenticator);
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
      log_dbg("Calling Station ID is: ");
      for (n=0; n<hismacattr->l-2; n++) log_dbg("%c", hismacattr->v.t[n]);
      log_dbg("\n");
    }
    if ((macstrlen = hismacattr->l-2) >= (RADIUS_ATTR_VLEN-1)) {
      log_err(0, "Wrong length of called station ID");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    memcpy(macstr,hismacattr->v.t, macstrlen);
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
    
    for(i = 0; i < DHCP_ETH_ALEN; i++) 
      hismac[i] = temp[i];
  }

  if (hismacattr) { /* Look for mac address.*/
    if (dhcp_hashget(dhcp, &dhcpconn, hismac)) {
      log_err(0, "Unknown connection");
      (void) radius_resp(radius, &radius_pack, peer, pack->authenticator);
      return 0;
    }
    if (!(dhcpconn->peer) || (!((struct app_conn_t*) dhcpconn->peer)->uplink)) {
      log_err(0,"No peer protocol defined");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    appconn = (struct app_conn_t*) dhcpconn->peer;
  }
  else if (nasipattr && nasportattr) { /* Look for NAS IP / Port */
    if (getconn(&appconn, nasip, nasport)) {
      log_err(0, "Unknown connection");
      (void) radius_resp(radius, &radius_pack, peer, pack->authenticator);
      return 0;
    }
  }
  else {
    log_err(0,
	    "Calling Station ID or NAS IP/Port is missing from radius request");
    (void) radius_resp(radius, &radius_pack, peer, pack->authenticator);
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
    dhcp_freeconn(dhcpconn);
    break;
  default:
    log_err(0,"Unknown downlink protocol");
    (void) radius_resp(radius, &radius_pack, peer, pack->authenticator);
    return 0;
  }

  (void) radius_resp(radius, &radius_pack, peer, pack->authenticator);

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
  int pwdlen;
  uint8_t hismac[DHCP_ETH_ALEN];
  char macstr[RADIUS_ATTR_VLEN];
  int macstrlen;
  unsigned int temp[DHCP_ETH_ALEN];
  int	i;
  char mac[MACSTRLEN+1];

  struct app_conn_t *appconn = NULL;
  struct dhcp_conn_t *dhcpconn = NULL;

  uint8_t resp[EAP_LEN];         /* EAP response */
  int resplen;                   /* Length of EAP response */

  int offset = 0;
  int instance = 0;
  int eaplen = 0;

  if (options.debug) log_dbg("Radius access request received!\n");

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
      log_dbg("Calling Station ID is: ");
      for (n=0; n<hismacattr->l-2; n++) log_dbg("%c", hismacattr->v.t[n]);
      log_dbg("\n");
    }
    if ((macstrlen = hismacattr->l-2) >= (RADIUS_ATTR_VLEN-1)) {
      log_err(0, "Wrong length of called station ID");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    memcpy(macstr,hismacattr->v.t, macstrlen);
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
    
    for(i = 0; i < DHCP_ETH_ALEN; i++) 
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
    
    if (!(ipm->peer) || (!((struct app_conn_t*) ipm->peer)->dnlink)) {
      log_err(0, "RADIUS-Request: No peer protocol defined");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    appconn = (struct app_conn_t*) ipm->peer;
    dhcpconn = (struct dhcp_conn_t*) appconn->dnlink;
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
    appconn = (struct app_conn_t*) dhcpconn->peer;
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
      if ((resplen + eapattr->l-2) > EAP_LEN) {
	log(LOG_INFO, "EAP message too long");
	return radius_resp(radius, &radius_pack, peer, pack->authenticator);
      }
      memcpy(resp+resplen, 
	     eapattr->v.t, eapattr->l-2);
      resplen += eapattr->l-2;
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
  if ((appconn->authenticated == 1) && 
      ((appconn->userlen != uidattr->l-2) ||
       (memcmp(appconn->user, uidattr->v.t, uidattr->l-2)))) {
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
    appconn->proxynasip = nasipattr->v.i;
  }

  /* NAS PORT */
  if (!radius_getattr(pack, &nasportattr, RADIUS_ATTR_NAS_PORT, 0, 0, 0)) {
    if ((nasportattr->l-2) != sizeof(appconn->nasport)) {
      log_err(0, "Wrong length of NAS port");
      return radius_resp(radius, &radius_pack, peer, pack->authenticator);
    }
    appconn->proxynasport = nasportattr->v.i;
  }

  /* Store parameters for later use */
  if (uidattr->l-2<=USERNAMESIZE) {
    memcpy(appconn->proxyuser, uidattr->v.t, uidattr->l-2);
    appconn->proxyuserlen = uidattr->l-2;
  }

  appconn->radiuswait = 1;
  appconn->radiusid = pack->id;

  if (pwdattr)
    appconn->authtype = PAP_PASSWORD;
  else
    appconn->authtype = EAP_MESSAGE;

  memcpy(&appconn->radiuspeer, peer, sizeof(*peer));
  memcpy(appconn->authenticator, pack->authenticator, RADIUS_AUTHLEN);
  memcpy(appconn->proxyhismac, dhcpconn->hismac, DHCP_ETH_ALEN);
  memcpy(appconn->proxyourmac, dhcpconn->ourmac, DHCP_ETH_ALEN);

  /* Build up radius request */
  radius_pack.code = RADIUS_CODE_ACCESS_REQUEST;
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
		 uidattr->v.t, uidattr->l - 2);

  if (appconn->statelen) {
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_STATE, 0, 0, 0,
		   appconn->statebuf,
		   appconn->statelen);
  }

  if (pwdattr)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
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
  (void) snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	   appconn->proxyhismac[0], appconn->proxyhismac[1],
	   appconn->proxyhismac[2], appconn->proxyhismac[3],
	   appconn->proxyhismac[4], appconn->proxyhismac[5]);
  
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0,
		 (uint8_t*) mac, MACSTRLEN);
  
  if (options.nasmac) {
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
		   (uint8_t *)options.nasmac, strlen(options.nasmac)); 
  } else {
    /* Include our MAC address */
    (void) snprintf(mac, MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
		    appconn->proxyourmac[0], appconn->proxyourmac[1],
		    appconn->proxyourmac[2], appconn->proxyourmac[3],
		    appconn->proxyourmac[4], appconn->proxyourmac[5]);
  }

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
		 (uint8_t*) mac, MACSTRLEN);
  
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		 options.radiusnasporttype, NULL, 0);

  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		 appconn->unit, NULL, 0);

  radius_addnasip(radius, &radius_pack);
  
  /* Include NAS-Identifier if given in configuration options */
  if (options.radiusnasid)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
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
  
  if (options.nodhcp) {
    log_err(0, "Radius request received when not using dhcp");
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
    ipm = (struct ippoolm_t*) appconn->uplink;
  }
  else {
    /* Allocate static or dynamic IP address */

    if (newip(&ipm, hisip))
      return dnprot_reject(appconn);

    /*    
    if ((hisip) && (statip)) {
      if (newip(&ipm, hisip))
	return dnprot_reject(appconn);
    }
    else {
      if (ippool_newip(ippool, &ipm, hisip, 0)) {
	log_err(0, "Failed to allocate dynamic IP address");
	return dnprot_reject(appconn);
      }
    }
    */

    appconn->hisip.s_addr = ipm->addr.s_addr;

    /* TODO: Listening address is network address plus 1 */
    appconn->ourip.s_addr = htonl((ntohl(options.net.s_addr)+1));
    
    appconn->uplink = ipm;
    ipm->peer   = appconn; 
  }

  return dnprot_accept(appconn);

}

void config_radius_session(struct session_params *params, struct radius_packet_t *pack, int reconfig) 
{
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
      log_err(0, "Received too small radius Acct-Interim-Interval value: %d. Disabling interim accounting",
	      params->interim_interval);
      params->interim_interval = 0;
    } 
    else if (params->interim_interval < 600) {
      log(LOG_WARNING, "Received small radius Acct-Interim-Interval value: %d",
	      params->interim_interval);
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

  {
    const char *uamauth = "require-uam-auth";
    const char *uamallowed = "uamallowed=";
    int offset = 0;

    /* Always reset the per session passthroughs */
    params->pass_through_count = 0;

    while (!radius_getnextattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			       RADIUS_VENDOR_CHILLISPOT, RADIUS_ATTR_CHILLISPOT_CONFIG, 
			       0, &offset)) { 
      size_t len = attr->l-2;
      char *val = (char*)attr->v.t;

      if (options.wpaguests && len == strlen(uamauth) && !memcmp(val, uamauth, len)) {
	params->require_uam_auth = 1;
      } 
      else if (len > strlen(uamallowed) && !memcmp(val, uamallowed, strlen(uamallowed))) {
	val[len]=0;
	pass_throughs_from_string(params->pass_throughs,
				  REDIR_PASS_THROUGH_MAX,
				  &params->pass_through_count,
				  val + strlen(uamallowed));
      }
    }

    offset = 0;
    params->url[0]=0;
    while (!radius_getnextattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
			       RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_REDIRECTION_URL, 
			       0, &offset)) { 
      size_t clen, nlen = attr->l-2;
      char *url = (char*)attr->v.t;
      clen = strlen(params->url);

      if (clen + nlen > sizeof(params->url)-1) 
	nlen = sizeof(params->url)-clen-1;

      strncpy(params->url + clen, url, nlen);
      params->url[nlen+clen]=0;
      params->require_redirect = 1;
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
  /*char attrs[RADIUS_ATTR_VLEN+1];*/
  int offset = 0;

  if (!pack) { 
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Radius request timed out");
    return 0;
  }

  if ((pack->code != RADIUS_CODE_ACCESS_REJECT) && 
      (pack->code != RADIUS_CODE_ACCESS_CHALLENGE) &&
      (pack->code != RADIUS_CODE_ACCESS_ACCEPT)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, 
	    "Unknown radius access reply code %d", pack->code);
    return 0;
  }

  /* ACCESS-ACCEPT */
  if (pack->code != RADIUS_CODE_ACCESS_ACCEPT) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Administrative-User Login Failed");
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

  admin_session.authenticated = 1;
  acct_req(&admin_session, RADIUS_STATUS_TYPE_START);

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
  appconn->statelen = 0;
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
      log_dbg("Received access reject from radius server\n");
    config_radius_session(&appconn->params, pack, 0); /*XXX*/
    return dnprot_reject(appconn);
  }

  /* ACCESS-CHALLENGE */
  if (pack->code == RADIUS_CODE_ACCESS_CHALLENGE) {
    if (options.debug)
      log_dbg("Received access challenge from radius server\n");

    /* Get EAP message */
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
    
    if (!appconn->challen) {
      log(LOG_INFO, "No EAP message found");
      return dnprot_reject(appconn);
    }
    
    /* Get State */
    if (!radius_getattr(pack, &stateattr, RADIUS_ATTR_STATE, 0, 0, 0)) {
      appconn->statelen = stateattr->l-2;
      memcpy(appconn->statebuf, stateattr->v.t, stateattr->l-2);
    }

    return dnprot_challenge(appconn);
  }
  
  /* ACCESS-ACCEPT */
  if (pack->code != RADIUS_CODE_ACCESS_ACCEPT) {
    log_err(0, "Unknown code of radius access request confirmation");
    return dnprot_reject(appconn);
  }

  /* Get State */
  if (!radius_getattr(pack, &stateattr, RADIUS_ATTR_STATE, 0, 0, 0)) {
    appconn->statelen = stateattr->l-2;
    memcpy(appconn->statebuf, stateattr->v.t, stateattr->l-2);
  }

  /* Class */
  if (!radius_getattr(pack, &classattr, RADIUS_ATTR_CLASS, 0, 0, 0)) {
    appconn->classlen = classattr->l-2;
    memcpy(appconn->classbuf, classattr->v.t, classattr->l-2);
  }
  else {
    appconn->classlen = 0;
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

  config_radius_session(&appconn->params, pack, 0);

  if (appconn->params.sessionterminatetime) {
    struct timeval timenow;
    gettimeofday(&timenow, NULL);
    if (timenow.tv_sec > appconn->params.sessionterminatetime) {
      log(LOG_WARNING, "WISPr-Session-Terminate-Time in the past received, rejecting");
      return dnprot_reject(appconn);
    }
  }

#ifdef LEAKY_BUCKET
  if (appconn->params.bandwidthmaxup) {
#ifdef BUCKET_SIZE
    appconn->bucketupsize = BUCKET_SIZE;
#else
    appconn->bucketupsize = appconn->bandwidthmaxup / 8000 * BUCKET_TIME;
    if (appconn->bucketupsize < BUCKET_SIZE_MIN) 
      appconn->bucketupsize = BUCKET_SIZE_MIN;
#endif
  }
#endif
  
#ifdef LEAKY_BUCKET
  if (appconn->params.bandwidthmaxdown) {
#ifdef BUCKET_SIZE
    appconn->bucketdownsize = BUCKET_SIZE;
#else
    appconn->bucketdownsize = params->bandwidthmaxdown / 8000 * BUCKET_TIME;
    if (appconn->bucketdownsize < BUCKET_SIZE_MIN) 
      appconn->bucketdownsize = BUCKET_SIZE_MIN;
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
    if (radius_keydecode(radius, appconn->sendkey, RADIUS_ATTR_VLEN, 
			 &appconn->sendlen, (uint8_t*) &sendattr->v.t,
			 sendattr->l-2, pack_req->authenticator,
			 radius->secret, radius->secretlen)) {
      log(LOG_INFO, "radius_keydecode() failed!");
      return dnprot_reject(appconn);
    }
  }
    
  /* Get recvkey */
  if (!radius_getattr(pack, &recvattr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_MS,
		      RADIUS_ATTR_MS_MPPE_RECV_KEY, 0)) {
    if (radius_keydecode(radius, appconn->recvkey, RADIUS_ATTR_VLEN,
			 &appconn->recvlen, (uint8_t*) &recvattr->v.t,
			 recvattr->l-2, pack_req->authenticator,
			 radius->secret, radius->secretlen) ) {
      log(LOG_INFO, "radius_keydecode() failed!");
      return dnprot_reject(appconn);
    }
  }

  /* Get LMNT keys */
  if (!radius_getattr(pack, &lmntattr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_MS,
		      RADIUS_ATTR_MS_CHAP_MPPE_KEYS, 0)) {

    /* TODO: Check length of vendor attributes */
    if (radius_pwdecode(radius, appconn->lmntkeys, RADIUS_MPPEKEYSSIZE,
			&appconn->lmntlen, (uint8_t*) &lmntattr->v.t,
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

    if ((appconn->authenticated) && 
	(appconn->userlen == uattr->l-2 && 
	 !memcmp(appconn->user, uattr->v.t, uattr->l-2)) &&
	(!sattr || 
	 (strlen(appconn->sessionid) == sattr->l-2 && 
	  !strncasecmp(appconn->sessionid, (char*)sattr->v.t, sattr->l-2)))) {

      if (options.debug)
	log_dbg("Found session\n");

      if (iscoa)
	config_radius_session(&appconn->params, pack, 0);
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
int cb_dhcp_request(struct dhcp_conn_t *conn, struct in_addr *addr) {
  struct ippoolm_t *ipm;
  struct app_conn_t *appconn = conn->peer;

  if (options.debug) 
    log_dbg("DHCP requested IP address");

  if (!appconn) {
    log_err(0, "Peer protocol not defined");
    return -1;
  }

  appconn->reqip.s_addr = addr->s_addr; /* Save for MAC auth later */

  /* If IP address is allready allocated: Fill it in */
  if (appconn->uplink) {
    ipm = (struct ippoolm_t*) appconn->uplink;
  }
  else if (appconn->dnprot == DNPROT_MAC) {
    log_dbg("Protocol MAC, returning.\n");
    return -1;
  }
  else if ((options.macauth) && 
	   (appconn->dnprot == DNPROT_DHCP_NONE) ){
    appconn->dnprot = DNPROT_MAC;
    macauth_radius(appconn);
    return -1;
  }
  else if ((options.macoklen) && 
	   (appconn->dnprot == DNPROT_DHCP_NONE) &&
	   !maccmp(conn->hismac)) {
    appconn->dnprot = DNPROT_MAC;
    if (options.macallowlocal) {
      upprot_getip(appconn, &appconn->reqip, 0);/**/
      dnprot_accept(appconn);
    } else {
      macauth_radius(appconn);    
    }
    return -1;
  }
  else {
    if (appconn->dnprot != DNPROT_DHCP_NONE) {
      log_err(0, "Requested IP address when allready allocated");
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

    /* TODO: Listening address is network address plus 1 */
    appconn->ourip.s_addr = htonl((ntohl(options.net.s_addr)+1));
    
    appconn->uplink =  ipm;
    ipm->peer   = appconn; 
  }
  
  dhcp_set_addrs(conn, &ipm->addr, &options.mask, &appconn->ourip,
		 &options.dns1, &options.dns2, options.domain);

  conn->authstate = DHCP_AUTH_DNAT;

  /* If IP was requested before authentication it was UAM */
  if (appconn->dnprot == DNPROT_DHCP_NONE)
    appconn->dnprot = DNPROT_UAM;

  /* ALPAPAD */
  /* Add routing entry ;-) */
  if (options.uamanyip) {
    if(ipm->inuse == 2) {
      struct in_addr mask;
      mask.s_addr = 0xffffffff;
      log_dbg("Adding route: %d\n", tun_addroute(tun,addr,&appconn->ourip,&mask));
    }
  }

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
  conn->peer  = appconn;

  appconn->net.s_addr = options.net.s_addr;
  appconn->mask.s_addr = options.mask.s_addr;
  appconn->dns1.s_addr = options.dns1.s_addr;
  appconn->dns2.s_addr = options.dns2.s_addr;

  memcpy(appconn->hismac, conn->hismac, DHCP_ETH_ALEN);
  memcpy(appconn->ourmac, conn->ourmac, DHCP_ETH_ALEN);
  memcpy(appconn->proxyhismac, conn->hismac, DHCP_ETH_ALEN);
  memcpy(appconn->proxyourmac, conn->ourmac, DHCP_ETH_ALEN);
  
  set_sessionid(appconn);

  conn->authstate = DHCP_AUTH_NONE; /* TODO: Not yet authenticated */

  return 0;
}

int cb_dhcp_getinfo(struct dhcp_conn_t *conn, char *b, int blen) {
  struct app_conn_t *appconn;
  struct timeval timenow;
  uint32_t sessiontime = 0;
  uint32_t idletime = 0;

  b[0]='-'; b[1]=0; 
  if (!conn->peer) return 2;
  appconn = (struct app_conn_t*) conn->peer;
  if (!appconn->inuse) return 2;

  gettimeofday(&timenow, NULL);

  if (appconn->authenticated) {
    sessiontime = timenow.tv_sec - appconn->start_time.tv_sec;
    sessiontime += (timenow.tv_usec - appconn->start_time.tv_usec) / 1000000;
    idletime = timenow.tv_sec - appconn->last_time.tv_sec;
    idletime += (timenow.tv_usec - appconn->last_time.tv_usec) / 1000000;
  }
  
   return snprintf(b, blen, "%.*s %d %.*s %d/%d %d/%d %.*s", 
		   appconn->sessionid[0] ? strlen(appconn->sessionid) : 1,
		   appconn->sessionid[0] ? appconn->sessionid : "-",
		   appconn->authenticated,
		   appconn->userlen ? appconn->userlen : 1,
		   appconn->userlen ? appconn->user : "-",
		   sessiontime, (int)appconn->params.sessiontimeout,
		   idletime, (int)appconn->params.idletimeout,
		   appconn->userurl[0] ? strlen(appconn->userurl) : 1,
		   appconn->userurl[0] ? appconn->userurl : "-");
}

int terminate_appconn(struct app_conn_t *appconn, int terminate_cause) {
  if (appconn->authenticated == 1) { /* Only send accounting if logged in */
    dnprot_terminate(appconn);
    appconn->terminate_cause = terminate_cause;
    acct_req(appconn, RADIUS_STATUS_TYPE_STOP);
    set_sessionid(appconn);
  }
  return 0;
}

/* Callback when a dhcp connection is deleted */
int cb_dhcp_disconnect(struct dhcp_conn_t *conn) {
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

  terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_LOST_CARRIER);

  /* ALPAPAD */
  if (appconn->uplink) {
    if (options.uamanyip) {
      struct ippoolm_t *member;
      member = (struct ippoolm_t *) appconn->uplink;
      if (member->inuse  == 2) {
	struct in_addr mask;
	mask.s_addr = 0xffffffff;
	printf("Removing route: %d\n", tun_delroute(tun,&member->addr,&appconn->ourip,&mask));
      }
    }
    if (ippool_freeip(ippool, (struct ippoolm_t *) appconn->uplink)) {
      log_err(0, "ippool_freeip() failed!");
    }
  }
  
  (void) freeconn(appconn);

  return 0;
}


/* Callback for receiving messages from dhcp */
int cb_dhcp_data_ind(struct dhcp_conn_t *conn, void *pack, unsigned len) {
  struct app_conn_t *appconn = conn->peer;
  /*struct dhcp_ethhdr_t *ethh = (struct dhcp_ethhdr_t *)pack;*/
  struct tun_packet_t *iph = (struct tun_packet_t*)(pack + DHCP_ETH_HLEN);

  /*if (options.debug)
    log_dbg("cb_dhcp_data_ind. Packet received. DHCP authstate: %d\n", 
    conn->authstate);*/

  if (iph->src != conn->hisip.s_addr) {
    if (options.debug) 
      log_dbg("Received packet with spoofed source!");
    return 0;
  }

  if (!appconn) {
    log_err(0, "No peer protocol defined");
    return -1;
  }

  /* If the ip dst is uamlisten and pdst is uamport we won't call leaky_bucket */
  if (iph->dst  == options.uamlisten.s_addr && 
      iph->pdst == htons(options.uamport))
    return tun_encaps(tun, pack, len);
  
  if (appconn->authenticated == 1) {

#ifndef LEAKY_BUCKET
    gettimeofday(&appconn->last_time, NULL);
#endif

#ifdef LEAKY_BUCKET
#ifndef COUNT_UPLINK_DROP
    if (leaky_bucket(appconn, len, 0)) return 0;
#endif
#endif
    if (options.swapoctets) {
      appconn->input_packets++;
      appconn->input_octets +=len;
      if (admin_session.authenticated) {
	admin_session.input_packets++;
	admin_session.input_octets+=len;
      }
    } else {
      appconn->output_packets++;
      appconn->output_octets +=len;
      if (admin_session.authenticated) {
	admin_session.output_packets++;
	admin_session.output_octets+=len;
      }
    }
#ifdef LEAKY_BUCKET
#ifdef COUNT_UPLINK_DROP
    if (leaky_bucket(appconn, len, 0)) return 0;
#endif
#endif
  }

  return tun_encaps(tun, pack, len);
}

/* Callback for receiving messages from eapol */
int cb_dhcp_eap_ind(struct dhcp_conn_t *conn, void *pack, unsigned len) {
  struct dhcp_eap_t *eap = (struct dhcp_eap_t*) pack;
  struct app_conn_t *appconn = conn->peer;
  struct radius_packet_t radius_pack;
  int offset;

  if (options.debug) log_dbg("EAP Packet received");

  /* If this is the first EAPOL authentication request */
  if ((appconn->dnprot == DNPROT_DHCP_NONE) || 
      (appconn->dnprot == DNPROT_EAPOL)) {
    if ((eap->code == 2) && /* Response */
	(eap->type == 1) && /* Identity */
	(len > 5) &&        /* Must be at least 5 octets */
	((len - 5) <= USERNAMESIZE )) {
      appconn->proxyuserlen = len -5;
      memcpy(appconn->proxyuser, eap->payload, appconn->proxyuserlen); 
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
    log_err(0, "Received EAP message when not authenticating using EAP!");
    return 0;
  }
  
  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REQUEST)) {
    log_err(0, "radius_default_pack() failed");
    return -1;
  }


  /* Build up radius request */
  radius_pack.code = RADIUS_CODE_ACCESS_REQUEST;
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
			(uint8_t*) appconn->proxyuser, appconn->proxyuserlen);

  if (appconn->statelen) {
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_STATE, 0, 0, 0,
		   appconn->statebuf,
		   appconn->statelen);
  }
  
  /* Include EAP (if present) */
  offset = 0;
  while (offset < len) {
    int eaplen;
    if ((len - offset) > RADIUS_ATTR_VLEN)
      eaplen = RADIUS_ATTR_VLEN;
    else
      eaplen = len - offset;
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_EAP_MESSAGE, 0, 0, 0,
		   pack + offset, eaplen);
    offset += eaplen;
  } 
  
  if (len)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		   0, 0, 0, NULL, RADIUS_MD5LEN);
  
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		 options.radiusnasporttype, NULL, 0);
  
  (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		 appconn->unit, NULL, 0);
  
  radius_addnasip(radius, &radius_pack);
  
  /* Include NAS-Identifier if given in configuration options */
  if (options.radiusnasid)
    (void) radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
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

  if (ippool_getip(ippool, &ipm, &msg->addr)) {
    if (options.debug) 
      log_dbg("UAM login with unknown IP address: %s", inet_ntoa(msg->addr));
    return 0;
  }

  if (!((ipm->peer) || ((struct app_conn_t*) ipm->peer)->dnlink)) {
    log_err(0, "No peer protocol defined");
    return 0;
  }

  appconn = (struct app_conn_t*) ipm->peer;
  dhcpconn = (struct dhcp_conn_t*) appconn->dnlink;

  switch(msg->type) {

  case REDIR_LOGIN:
    if (appconn->uamabort) {
      sys_err(LOG_NOTICE, __FILE__, __LINE__, 0,
	      "UAM login from username=%s IP=%s was aborted!", 
	      msg->username, inet_ntoa(appconn->hisip));
      appconn->uamabort = 0;
      return 0;
    }

    sys_err(LOG_NOTICE, __FILE__, __LINE__, 0,
	    "Successful UAM login from username=%s IP=%s", 
	    msg->username, inet_ntoa(appconn->hisip));
    
    if (options.debug)
      log_dbg("Received login from UAM\n");
    
    /* Initialise */
    appconn->statelen = 0;
    appconn->challen  = 0;
    appconn->sendlen  = 0;
    appconn->recvlen  = 0;
    appconn->lmntlen  = 0;
    
    /* Store user name for accounting records */
    strncpy(appconn->user, msg->username, USERNAMESIZE);
    appconn->userlen = strlen(msg->username);

    strncpy(appconn->proxyuser, msg->username, USERNAMESIZE);
    appconn->proxyuserlen = strlen(msg->username);

    memcpy(appconn->hismac, dhcpconn->hismac, DHCP_ETH_ALEN);
    memcpy(appconn->ourmac, dhcpconn->ourmac, DHCP_ETH_ALEN);
    memcpy(appconn->proxyhismac, dhcpconn->hismac, DHCP_ETH_ALEN);
    memcpy(appconn->proxyourmac, dhcpconn->ourmac, DHCP_ETH_ALEN);
    
    appconn->policy = 0; /* TODO */

    appconn->statelen = msg->statelen;
    memcpy(appconn->statebuf, msg->statebuf, msg->statelen);
    appconn->classlen = msg->classlen;
    memcpy(appconn->classbuf, msg->classbuf, msg->classlen);

    memcpy(&appconn->params, &msg->params, sizeof(msg->params));

#ifdef LEAKY_BUCKET
#ifdef BUCKET_SIZE
    appconn->bucketupsize = BUCKET_SIZE;
#else
    appconn->bucketupsize = appconn->bandwidthmaxup / 8000 * BUCKET_TIME;
    if (appconn->bucketupsize < BUCKET_SIZE_MIN) 
      appconn->bucketupsize = BUCKET_SIZE_MIN;
#endif
#endif

#ifdef LEAKY_BUCKET
#ifdef BUCKET_SIZE
    appconn->bucketdownsize = BUCKET_SIZE;
#else
    appconn->bucketdownsize = appconn->bandwidthmaxdown / 8000 * BUCKET_TIME;
    if (appconn->bucketdownsize < BUCKET_SIZE_MIN) 
      appconn->bucketdownsize = BUCKET_SIZE_MIN;
#endif
#endif

    if (msg->userurl[0]) {
      strncpy(appconn->userurl, msg->userurl, USERURLSIZE);
      appconn->userurl[USERURLSIZE-1] = 0;
    }

    return upprot_getip(appconn, NULL, 0);

  case REDIR_LOGOUT:

    sys_err(LOG_NOTICE, __FILE__, __LINE__, 0,
	    "Received UAM logoff from username=%s IP=%s",
	    appconn->user, inet_ntoa(appconn->hisip));

    if (options.debug)
      log_dbg("Received logoff from UAM\n");

    if (appconn->authenticated == 1) {
      terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_USER_REQUEST);
      appconn->uamtime = 0;
      appconn->userurl[0] = 0;    
      appconn->user[0] = 0;
      appconn->userlen = 0;
      appconn->params.sessiontimeout = 0;
      appconn->params.idletimeout = 0;
    }

    memcpy(appconn->uamchal, msg->uamchal, REDIR_MD5LEN);
    appconn->uamtime = time(NULL);
    appconn->uamabort = 0;
    dhcpconn->authstate = DHCP_AUTH_DNAT;

    break;

  case REDIR_ABORT:
    
    sys_err(LOG_NOTICE, __FILE__, __LINE__, 0,
	    "Received UAM abort from IP=%s", inet_ntoa(appconn->hisip));

    appconn->uamabort = 1; /* Next login will be aborted */
    appconn->uamtime = 0;  /* Force generation of new challenge */
    dhcpconn->authstate = DHCP_AUTH_DNAT;

    terminate_appconn(appconn, RADIUS_TERMINATE_CAUSE_USER_REQUEST);

    break;

  case REDIR_CHALLENGE:
    memcpy(appconn->uamchal, msg->uamchal, REDIR_MD5LEN);
    appconn->uamtime = time(NULL);
    appconn->uamabort = 0;
    if (msg->userurl[0]) {
      strncpy(appconn->userurl, msg->userurl, USERURLSIZE);
      appconn->userurl[USERURLSIZE-1] = 0;
    }
    break;

  case REDIR_NOTYET:
    appconn->classlen = msg->classlen;
    memcpy(appconn->classbuf, msg->classbuf, msg->classlen);
    memcpy(&appconn->params, &msg->params, sizeof(msg->params));
    break;
  }

  return 0;
}

static int cmdsock_accept(int sock) {
  struct sockaddr_un remote; 
  struct cmdsock_request req;

  unsigned int len;
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
    if (dhcp) dhcp_list(dhcp, csock, 0);
    break;

  case CMDSOCK_DHCP_RELEASE:
    if (dhcp) dhcp_release_mac(dhcp, req.data.mac);
    break;

  case CMDSOCK_LIST:
    if (dhcp) dhcp_list(dhcp, csock, 1);
    break;

  case CMDSOCK_SHOW:
    /*ToDo*/
    break;

  case CMDSOCK_AUTHORIZE:
    if (dhcp) {
      struct dhcp_conn_t *dhcpconn = dhcp->firstusedconn;
      log_dbg("looking to authorized session %s",inet_ntoa(req.data.sess.ip));
      while (dhcpconn && dhcpconn->inuse) {
	if (dhcpconn->peer) {
	  struct app_conn_t * appconn = (struct app_conn_t*) dhcpconn->peer;
	  if (  (req.data.sess.ip.s_addr == 0    || appconn->hisip.s_addr == req.data.sess.ip.s_addr) &&
		(req.data.sess.sessionid[0] == 0 || !strcmp(appconn->sessionid,req.data.sess.sessionid))
		){
	    char *uname = req.data.sess.username;
	    log_dbg("remotely authorized session %s",appconn->sessionid);
	    memcpy(&appconn->params, &req.data.sess.params, sizeof(req.data.sess.params));
	    if (!uname[0]) uname = "anonymous";
	    strncpy(appconn->proxyuser, uname, USERNAMESIZE);
	    appconn->proxyuserlen = strlen(uname);
	    strncpy(appconn->user, uname, USERNAMESIZE);
	    appconn->userlen = strlen(uname);
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

  close(csock);
  shutdown(csock, 2);
  return rval;
}

/* Function that will create and write a status file in statedir*/
int printstatus(struct app_conn_t *appconn)
{
  struct app_conn_t *apptemp;
  FILE *file;
  char filedest[512];
  struct timeval timenow;
  struct stat statbuf;

  if (!options.usestatusfile) return 0;
  if (!options.statedir) return 0;
  if (strlen(options.statedir)>sizeof(filedest)-1) return -1;
  if (stat(options.statedir, &statbuf)) { log_err(errno, "statedir does not exist"); return -1; }
  if (!S_ISDIR(statbuf.st_mode)) { log_err(0, "statedir not a directory"); return -1; }

  gettimeofday(&timenow, NULL);
  strcpy(filedest, options.statedir);
  strcat(filedest, "/chillispot.state");

  file = fopen(filedest, "w");
  if (!file) { log_err(errno, "could not open file %s", filedest); return -1; }
  fprintf(file, "#Version:1.1\n");
  fprintf(file, "#SessionID = SID\n#Start-Time = ST\n");
  fprintf(file, "#SessionTimeOut = STO\n#SessionTerminateTime = STT\n");
  fprintf(file, "#Timestamp: %d\n", timenow.tv_sec);
  fprintf(file, "#User, IP, MAC, SID, ST, STO, STT\n");
  if(appconn == NULL)
  {
    fclose(file);
    return 0;
  }
  apptemp = appconn;
  while(apptemp != NULL)
  {
    if(apptemp->authenticated==1)
    {
      fprintf(file, "%s, %s, %.2X-%.2X-%.2X-%.2X-%.2X-%.2X, %s, %d, %d, %d\n",
	apptemp->user,
	inet_ntoa(apptemp->hisip),
	apptemp->hismac[0], apptemp->hismac[1],
	apptemp->hismac[2], apptemp->hismac[3],
	apptemp->hismac[4], apptemp->hismac[5],
	apptemp->sessionid,
	(apptemp->start_time).tv_sec,
	apptemp->params.sessiontimeout,
	apptemp->params.sessionterminatetime);
    }
    apptemp = apptemp->prev;
  }
  apptemp = appconn->next;
  while(apptemp != NULL)
  {
    if(apptemp->authenticated==1)
    {
      fprintf(file, "%s, %s, %.2X-%.2X-%.2X-%.2X-%.2X-%.2X, %s, %d, %d, %d\n",
	apptemp->user,
	inet_ntoa(apptemp->hisip),
	apptemp->hismac[0], apptemp->hismac[1],
	apptemp->hismac[2], apptemp->hismac[3],
	apptemp->hismac[4], apptemp->hismac[5],
	apptemp->sessionid,
	(apptemp->start_time).tv_sec,
	apptemp->params.sessiontimeout,
	apptemp->params.sessionterminatetime);
    }
    apptemp = apptemp->next;
  }
  fclose(file);
  return 0;
}

int chilli_main(int argc, char **argv)
{
  
  int maxfd = 0;	                /* For select() */
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
    (void) freopen("/dev/null", "w", stdout);
    (void) freopen("/dev/null", "w", stderr);
    (void) freopen("/dev/null", "r", stdin);
    if (daemon(1, 1)) {
      log_err(errno, "daemon() failed!");
    }
  } 

  if (options.logfacility<0||options.logfacility>LOG_NFACILITIES)
    options.logfacility=LOG_FAC(LOG_LOCAL6);

  closelog(); 
  openlog(PACKAGE, LOG_PID, (options.logfacility<<3));
  
  /* This has to be done after we have our final pid */
  if (options.pidfile) {
    log_pid(options.pidfile);
  }

  printstatus(NULL);

  /* Create a tunnel interface */
  if (tun_new((struct tun_t**) &tun, options.txqlen)) {
    log_err(0, "Failed to create tun");
    exit(1);
  }

  /*tun_setaddr(tun, &options.dhcplisten,  &options.net, &options.mask);*/
  tun_setaddr(tun, &options.dhcplisten,  &options.dhcplisten, &options.mask);
  tun_set_cb_ind(tun, cb_tun_ind);

  if (tun->fd > maxfd) maxfd = tun->fd;
  if (options.ipup) tun_runscript(tun, options.ipup);

  
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
  
  radius_set(radius, (options.debug & DEBUG_RADIUS));
  
  if (options.debug) 
    log_dbg("ChilliSpot version %s started.\n", VERSION);

  syslog(LOG_INFO, "ChilliSpot %s. Copyright 2002-2005 Mondru AB. Licensed under GPL. "
	 "Copyright 2006-2007 David Bird <dbird@acm.org>. Licensed under GPL. "
	 "See http://www.chillispot.org/ & http://coova.org/ for details.", VERSION);
  
  radius_set_cb_auth_conf(radius, cb_radius_auth_conf);
  radius_set_cb_ind(radius, cb_radius_ind);
  radius_set_cb_coa_ind(radius, cb_radius_coa_ind);

  acct_req(&admin_session, RADIUS_STATUS_TYPE_ACCOUNTING_ON);

  if (options.adminuser) {
    admin_session.is_adminsession = 1;
    strncpy(admin_session.user, options.adminuser, sizeof(admin_session.user));
    admin_session.userlen = strlen(options.adminuser);
    set_sessionid(&admin_session);
    chilliauth_radius(radius);
  }

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
  redir_set(redir, (options.debug & DEBUG_REDIR));
  redir_set_cb_getstate(redir, cb_redir_getstate);
  
  /* Create an instance of dhcp */
  if (!options.nodhcp) {
    if (dhcp_new(&dhcp, APP_NUM_CONN, options.dhcpif,
		 options.dhcpusemac, options.dhcpmac, options.dhcpusemac, 
		 &options.dhcplisten, options.lease, 1, 
		 &options.uamlisten, options.uamport, 
		 options.eapolenable)) {
      log_err(0, "Failed to create dhcp");
      exit(1);
    }
    if (dhcp->fd > maxfd)
      maxfd = dhcp->fd;
    if (dhcp->arp_fd > maxfd)
      maxfd = dhcp->arp_fd;
    if (dhcp->eapol_fd > maxfd)
      maxfd = dhcp->eapol_fd;
    
    (void) dhcp_set_cb_request(dhcp, cb_dhcp_request);
    (void) dhcp_set_cb_connect(dhcp, cb_dhcp_connect);
    (void) dhcp_set_cb_disconnect(dhcp, cb_dhcp_disconnect);
    (void) dhcp_set_cb_data_ind(dhcp, cb_dhcp_data_ind);
    (void) dhcp_set_cb_eap_ind(dhcp, cb_dhcp_eap_ind);
    (void) dhcp_set_cb_getinfo(dhcp, cb_dhcp_getinfo);
    if (dhcp_set(dhcp, (options.debug & DEBUG_DHCP))) {
      log_err(0, "Failed to set DHCP parameters");
      exit(1);
    }

  }

  if (options.cmdsocket) {
    struct sockaddr_un local;
    int len;
    
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
  }

  if (cmdsock > 0) maxfd = cmdsock;


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

  while (keep_going) {

    if (do_sighup) {
      reprocess_options(argc, argv);
      do_sighup = 0;

      /* Reinit DHCP parameters */
      if (dhcp)
	dhcp_set(dhcp, (options.debug & DEBUG_DHCP));
      
      /* Reinit RADIUS parameters */
      radius_set(radius, (options.debug & DEBUG_RADIUS));
      
      /* Reinit Redir parameters */
      redir_set(redir, (options.debug & DEBUG_REDIR));

      chilliauth_radius(radius);
    }

    if (lastSecond != (thisSecond = time(NULL)) /*do_timeouts*/) {
      radius_timeout(radius);

      if (dhcp) 
	dhcp_timeout(dhcp);
      
      checkconn();
      lastSecond = thisSecond;
      /*do_timeouts = 0;*/
    }

    FD_ZERO(&fds);
    if (tun && tun->fd != -1) FD_SET(tun->fd, &fds);
    if (dhcp) {
      FD_SET(dhcp->fd, &fds);
#if defined(__linux__)
      if (dhcp->arp_fd) FD_SET(dhcp->arp_fd, &fds);
      if (dhcp->eapol_fd) FD_SET(dhcp->eapol_fd, &fds);
#endif
    }
    if (radius->fd != -1) FD_SET(radius->fd, &fds);
    if (radius->proxyfd != -1) FD_SET(radius->proxyfd, &fds);
    if (redir->fd[0] > 0) FD_SET(redir->fd[0], &fds);
    if (redir->fd[1] > 0) FD_SET(redir->fd[1], &fds);
    if (cmdsock != -1) FD_SET(cmdsock, &fds);

    idleTime.tv_sec = 1; /*IDLETIME;*/
    idleTime.tv_usec = 0;
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

    if ((msgresult = msgrcv(redir->msgid, (struct msgbuf*) &msg, sizeof(msg), 
			   0, IPC_NOWAIT)) < 0) {
      if ((errno != EAGAIN) && (errno != ENOMSG))
	log_err(errno, "msgrcv() failed!");
    }

    if (msgresult > 0) (void) uam_msg(&msg);
    
    if (status > 0) {

      if (tun && 
	  tun->fd != -1 && 
	  FD_ISSET(tun->fd, &fds) && 
	  tun_decaps(tun) < 0) {
	log_err(0, "tun_decaps failed!");
      }
     
      if (dhcp) {
#if defined(__linux__)

	if (FD_ISSET(dhcp->fd, &fds) && 
	    dhcp_decaps(dhcp) < 0) {
	  log_err(0, "dhcp_decaps() failed!");
	}
      
	if (FD_ISSET(dhcp->arp_fd, &fds) && 
	    dhcp_arp_ind(dhcp) < 0) {
	  log_err(0, "dhcp_arpind() failed!");
	}
	
	if (dhcp->eapol_fd && 
	    FD_ISSET(dhcp->eapol_fd, &fds) && 
	    dhcp_eapol_ind(dhcp) < 0) {
	  log_err(0, "dhcp_eapol_ind() failed!");
	}

#elif defined (__FreeBSD__)  || defined (__APPLE__) || defined (__OpenBSD__)
	if (FD_ISSET(dhcp->fd, &fds) && 
	    dhcp_receive(dhcp) < 0) {
	  log_err(0, "dhcp_decaps() failed!");
	}
#endif
      }

      if (radius->fd != -1 && 
	  FD_ISSET(radius->fd, &fds) && 
	  radius_decaps(radius) < 0) {
	log_err(0, "radius_ind() failed!");
      }

      if (radius->proxyfd != -1 && 
	  FD_ISSET(radius->proxyfd, &fds) && 
	  radius_proxy_ind(radius) < 0) {
	log_err(0, "radius_proxy_ind() failed!");
      }

      if (redir->fd[0] > 0 && 
	  FD_ISSET(redir->fd[0], &fds) && 
	  redir_accept(redir, 0) < 0) {
	log_err(0, "redir_accept() failed!");
      }

      if (redir->fd[1] > 0 && 
	  FD_ISSET(redir->fd[1], &fds) && 
	  redir_accept(redir, 1) < 0) {
	log_err(0, "redir_accept() failed!");
      }
      
      if (cmdsock != -1 && 
	  FD_ISSET(cmdsock, &fds) && 
	  cmdsock_accept(cmdsock) < 0) {
	log_err(0, "cmdsock_accept() failed!");
      }
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
