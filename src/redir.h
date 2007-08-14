/* 
 *
 * HTTP redirection functions.
 * Copyright (C) 2004, 2005 Mondru AB.
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */


#ifndef _REDIR_H
#define _REDIR_H

#define REDIR_MAXLISTEN 3

#define REDIR_MAXTIME 100  /* Seconds */

#define REDIR_HTTP_MAX_TIME    10      /* Seconds */
#define REDIR_HTTP_SELECT_TIME 500000  /* microseconds = 0.5 seconds */

#define REDIR_RADIUS_MAX_TIME    60      /* Seconds */
#define REDIR_RADIUS_SELECT_TIME 500000  /* microseconds = 0.5 seconds */

#define REDIR_TERM_INIT     0  /* Nothing done yet */
#define REDIR_TERM_GETREQ   1  /* Before calling redir_getreq */
#define REDIR_TERM_GETSTATE 2  /* Before calling cb_getstate */
#define REDIR_TERM_PROCESS  3  /* Started to process request */
#define REDIR_TERM_RADIUS   4  /* Calling radius */
#define REDIR_TERM_REPLY    5  /* Sending response to client */

#define REDIR_CHALLEN 16
#define REDIR_MD5LEN 16

#define REDIR_MACSTRLEN 17

/*#define REDIR_MAXCHAR 1024*/
#define REDIR_MAXCHAR 64

#define REDIR_MAXBUFFER 5125

#define REDIR_USERNAMESIZE 256 /* Max length of username */
#define REDIR_MAXQUERYSTRING 2048
#define REDIR_USERURLSIZE    2048  /* Max length of URL requested by user */
#define REDIR_USERAGENTSIZE 256
#define REDIR_LANGSIZE 16
#define REDIR_IDENTSIZE 16

#define REDIR_MAXCONN 16

#define REDIR_CHALLENGETIMEOUT1 300 /* Seconds */
#define REDIR_CHALLENGETIMEOUT2 600 /* Seconds */

#define REDIR_URL_LEN    2048

#define REDIR_LOGIN      1
#define REDIR_PRELOGIN   2
#define REDIR_LOGOUT     3
#define REDIR_CHALLENGE  4
#define REDIR_ABORT      5
#define REDIR_ABOUT      6
#define REDIR_STATUS     7
#define REDIR_WWW        20
#define REDIR_MSDOWNLOAD 25
#define REDIR_ADMIN_CONN 30

#define REDIR_FMT_DEFAULT 0
#define REDIR_FMT_JSON    1

#define REDIR_ALREADY        50 /* Reply to /logon while allready logged on */
#define REDIR_FAILED_REJECT  51 /* Reply to /logon if authentication reject */
#define REDIR_FAILED_OTHER   52 /* Reply to /logon if authentication timeout */
#define REDIR_SUCCESS    53 /* Reply to /logon if authentication successful */
#define REDIR_LOGOFF     54 /* Reply to /logff */
#define REDIR_NOTYET     55 /* Reply to /prelogin or any GET request */
#define REDIR_ABORT_ACK  56 /* Reply to /abortlogin */
#define REDIR_ABORT_NAK  57 /* Reply to /abortlogin */

#define REDIR_ETH_ALEN  6
#define REDIR_SESSIONID_LEN 17
#define REDIR_PASS_THROUGH_MAX 4

#include "garden.h"

struct session_params {
  char url[REDIR_USERURLSIZE];
  char filteridbuf[RADIUS_ATTR_VLEN+1];
  unsigned char filteridlen;
  unsigned long bandwidthmaxup;
  unsigned long bandwidthmaxdown;
  unsigned long maxinputoctets;
  unsigned long maxoutputoctets;
  unsigned long maxtotaloctets;
  unsigned long sessiontimeout;
  unsigned short idletimeout;
  unsigned short interim_interval;     /* Seconds. 0 = No interim accounting */
  time_t sessionterminatetime;
  char require_uam_auth;
  char require_redirect;

  pass_through pass_throughs[REDIR_PASS_THROUGH_MAX];
  int pass_through_count;
} __attribute__((packed));

struct redir_conn_t {
  /* Parameters from HTTP request */
  unsigned short type; /* REDIR_LOGOUT, LOGIN, PRELOGIN, CHALLENGE, MSDOWNLOAD */
  unsigned char format; /* REDIR_FMT_DEFAULT, REDIR_FMT_JSON */

  char username[REDIR_USERNAMESIZE];
  char sessionid[REDIR_SESSIONID_LEN]; /* Accounting session ID */
  char userurl[REDIR_USERURLSIZE];
  char useragent[REDIR_USERAGENTSIZE];
  char lang[REDIR_LANGSIZE];
  char wwwfile[REDIR_USERNAMESIZE];

  int chap; /* 0 if using normal password; 1 if using CHAP */
  uint8_t chappassword[REDIR_MAXCHAR];
  uint8_t password[REDIR_MAXCHAR];
  
  unsigned char chap_ident;

  /* Challenge as sent to web server */
  uint8_t uamchal[REDIR_MD5LEN];
  int uamtime;

  int authenticated;           /* 1 if user was authenticated */  
  struct in_addr nasip;
  uint32_t nasport;
  uint8_t hismac[REDIR_ETH_ALEN];    /* His MAC address */
  uint8_t ourmac[REDIR_ETH_ALEN];    /* Our MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in_addr hisip;        /* Client IP address */
  int response; /* 0: No radius response yet; 1:Reject; 2:Accept; 3:Timeout */

  char replybuf[RADIUS_ATTR_VLEN+1];
  char *reply;

  uint8_t statebuf[RADIUS_ATTR_VLEN+1];
  unsigned char statelen;
  uint8_t classbuf[RADIUS_ATTR_VLEN+1];
  unsigned char classlen;

  uint64_t input_octets;     /* Transferred in callback */
  uint64_t output_octets;    /* Transferred in callback */
  time_t start_time; /* Transferred in callback */
  time_t last_time;  /* Transferred in callback */

  struct session_params params;
};

struct redir_t {
  int fd[2];             /* File descriptors */
  int debug;
  int msgid;             /* Message Queue */
  struct in_addr addr;
  int port;
  int uiport;
  char *url;
  char *homepage;
  char *secret;
  char *ssid;
  char *nasmac;
  char *nasip;
  struct in_addr radiuslisten;
  struct in_addr radiusserver0;
  struct in_addr radiusserver1;
  uint16_t radiusauthport;
  uint16_t radiusacctport;
  char *radiussecret;
  char *radiusnasid;
  char* radiuslocationid;
  char* radiuslocationname;
  char* locationname;
  int radiusnasporttype;
  int starttime;
  int chillixml;     /* Send chilli specific XML along with WISPr */
  int no_uamsuccess; /* Do not redirect back to uamserver on success */
  int no_uamwispr;   /* Do not have Chilli return WISPr blocks */
  int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
		      struct redir_conn_t *conn);
};


struct redir_msg_t {
  long int type;
  struct in_addr addr;
  char username[REDIR_USERNAMESIZE];
  char userurl[REDIR_USERURLSIZE];
  uint8_t uamchal[REDIR_MD5LEN];
  uint8_t statebuf[RADIUS_ATTR_VLEN+1];
  int statelen;
  uint8_t classbuf[RADIUS_ATTR_VLEN+1];
  int classlen;
  struct session_params params;
} __attribute__((packed));


extern int redir_new(struct redir_t **redir,
		     struct in_addr *addr, int port, int uiport);

extern int redir_free(struct redir_t *redir);

extern void redir_set(struct redir_t *redir, int debug);

extern int redir_accept(struct redir_t *redir, int idx);

extern int redir_setchallenge(struct redir_t *redir, struct in_addr *addr,
			      unsigned char *challenge);

extern int redir_set_cb_getstate(struct redir_t *redir,
  int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
		      struct redir_conn_t *conn));

int redir_main(struct redir_t *redir, int infd, int outfd, struct sockaddr_in *address, int isui);

#endif	/* !_REDIR_H */
