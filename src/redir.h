/* 
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

#include "dhcp.h"
#include "session.h"

#define REDIR_TERM_INIT       0  /* Nothing done yet */
#define REDIR_TERM_GETREQ     1  /* Before calling redir_getreq */
#define REDIR_TERM_GETSTATE   2  /* Before calling cb_getstate */
#define REDIR_TERM_PROCESS    3  /* Started to process request */
#define REDIR_TERM_RADIUS     4  /* Calling radius */
#define REDIR_TERM_REPLY      5  /* Sending response to client */

#define REDIR_LOGIN           1
#define REDIR_PRELOGIN        2
#define REDIR_LOGOUT          3
#define REDIR_CHALLENGE       4
#define REDIR_ABORT           5
#define REDIR_ABOUT           6
#define REDIR_STATUS          7
#define REDIR_WWW            20
#define REDIR_MSDOWNLOAD     25
#define REDIR_ADMIN_CONN     30
#define REDIR_ALREADY        50 /* Reply to /logon while allready logged on */
#define REDIR_FAILED_REJECT  51 /* Reply to /logon if authentication reject */
#define REDIR_FAILED_OTHER   52 /* Reply to /logon if authentication timeout */
#define REDIR_SUCCESS        53 /* Reply to /logon if authentication successful */
#define REDIR_LOGOFF         54 /* Reply to /logff */
#define REDIR_NOTYET         55 /* Reply to /prelogin or any GET request */
#define REDIR_ABORT_ACK      56 /* Reply to /abortlogin */
#define REDIR_ABORT_NAK      57 /* Reply to /abortlogin */

#define REDIR_FMT_DEFAULT     0
#define REDIR_FMT_JSON        1

#define REDIR_MSG_OPT_REDIR   1
#define REDIR_MSG_OPT_PARAMS  2

struct redir_conn_t {
  /* 
   *  Parameters from HTTP request 
   */
  unsigned short type;                 /* REDIR_LOGOUT, LOGIN, PRELOGIN, CHALLENGE, MSDOWNLOAD */
  unsigned char format;                /* REDIR_FMT_DEFAULT, REDIR_FMT_JSON */
  char useragent[REDIR_USERAGENTSIZE]; /* Browser User-Agent */
  char lang[REDIR_LANGSIZE];           /* Query string parameter for language */
  char wwwfile[REDIR_USERNAMESIZE];    /* File request, i.e. PATH_INFO */

  /*
   *  Authentication state information
   */
  int chap; /* 0 if using normal password; 1 if using CHAP */
  int response; /* 0: No radius response yet; 1:Reject; 2:Accept; 3:Timeout */
  uint8_t chappassword[REDIR_MAXCHAR];
  uint8_t password[REDIR_MAXCHAR];
  uint8_t chap_ident;
  
  /* 
   *  RADIUS session parameters 
   */
  struct in_addr nasip;
  uint32_t nasport;
  uint8_t hismac[PKT_ETH_ALEN];/* His MAC address */
  uint8_t ourmac[PKT_ETH_ALEN];/* Our MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in_addr hisip;        /* Client IP address */

  /*
   *  RADIUS Reply-Message
   */
  char replybuf[RADIUS_ATTR_VLEN+1];
  char *reply;

  /*
   *  Chilli Session parameters and status
   */
  struct session_params params;
  struct session_state state;
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
  long mtype;
  struct redir_msg_data {
    uint16_t opt;
    struct in_addr addr;
    struct redir_state redir;
    struct session_params params;
  } mdata;
};


int redir_new(struct redir_t **redir, struct in_addr *addr, int port, int uiport);

int redir_free(struct redir_t *redir);

void redir_set(struct redir_t *redir, int debug);

int redir_accept(struct redir_t *redir, int idx);

int redir_setchallenge(struct redir_t *redir, struct in_addr *addr, uint8_t *challenge);

int redir_set_cb_getstate(struct redir_t *redir,
  int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
		      struct redir_conn_t *conn));

int redir_main(struct redir_t *redir, int infd, int outfd, struct sockaddr_in *address, int isui);

int redir_json_fmt_redir(struct redir_conn_t *conn, bstring json, 
			 char *userurl, char *redirurl, uint8_t *hismac);

int redir_json_fmt_session(struct redir_conn_t *conn, bstring json, int init);

#endif	/* !_REDIR_H */
