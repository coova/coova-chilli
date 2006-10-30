/* 
 *
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (c) 2006 Coova Technologies Ltd
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 * The initial developer of the original code is
 * Jens Jakobsen <jj@chillispot.org>
 *
 */

#ifndef _CHILLI_H
#define _CHILLI_H

/* If the constants below are defined packets which have been dropped
   by the traffic shaper will be counted towards accounting and
   volume limitation */
/* #define COUNT_DOWNLINK_DROP 1 */
/* #define COUNT_UPLINK_DROP 1 */
#define LEAKY_BUCKET 1

#define APP_NUM_CONN 1024
#define EAP_LEN 2048            /* TODO: Rather large */

#define MACOK_MAX 16

#define MACSTRLEN 17

#define MS2SUCCSIZE 40	/* MS-CHAPv2 authenticator response as ASCII */

#define DATA_LEN 1500    /* Max we allow */

#define USERNAMESIZE 256 /* Max length of username */
#define CHALLENGESIZE 24 /* From chap.h MAX_CHALLENGE_LENGTH */
#define USERURLSIZE 256  /* Max length of URL requested by user */

#define BUCKET_SIZE  300000 /* Size of leaky bucket (~200 packets) */

/* Time length of leaky bucket in milliseconds */
/* Bucket size = BUCKET_TIME * Bandwidth-Max radius attribute */
/* Not used if BUCKET_SIZE is defined */
#define BUCKET_TIME  5000  /* 5 seconds */
#define BUCKET_SIZE_MIN  15000 /* Minimum size of leaky bucket (~10 packets) */

#define CHECK_INTERVAL 3   /* Time between checking connections */


/* Authtype defs */
#define CHAP_DIGEST_MD5   0x05
#define CHAP_MICROSOFT    0x80
#define CHAP_MICROSOFT_V2 0x81
#define PAP_PASSWORD       256
#define EAP_MESSAGE        257

#define MPPE_KEYSIZE  16
#define NT_KEYSIZE    16


#define DNPROT_DHCP_NONE  2
#define DNPROT_UAM        3
#define DNPROT_WPA        4
#define DNPROT_EAPOL      5
#define DNPROT_MAC        6

/* Debug facility */
#define DEBUG_DHCP        2
#define DEBUG_RADIUS      4
#define DEBUG_REDIR       8
#define DEBUG_CONF       16

/* Struct information for each connection */
struct app_conn_t {
  
  /* Management of connections */
  int inuse;
  int unit;
  struct app_conn_t *next;    /* Next in linked list. 0: Last */
  struct app_conn_t *prev;    /* Previous in linked list. 0: First */

  char username[REDIR_USERNAMESIZE];
  char sessionid[REDIR_SESSIONID_LEN]; /* Accounting session ID */

  struct session_params params; /* Session parameters */

  /* Pointers to protocol handlers */
  void *uplink;                  /* Uplink network interface (Internet) */
  void *dnlink;                  /* Downlink network interface (Wireless) */
  int dnprot;                    /* Downlink protocol */

  /* Radius authentication stuff */
  /* Parameters are initialised whenever a reply to an access request
     is received. */
  uint8_t chal[EAP_LEN];         /* EAP challenge */
  int challen;                   /* Length of EAP challenge */
  uint8_t sendkey[RADIUS_ATTR_VLEN];
  uint8_t recvkey[RADIUS_ATTR_VLEN];
  uint8_t lmntkeys[RADIUS_MPPEKEYSSIZE];
  int sendlen;
  int recvlen;
  int lmntlen;
  uint32_t policy;
  uint32_t types;
  uint8_t ms2succ[MS2SUCCSIZE];
  int ms2succlen;
  uint8_t statebuf[RADIUS_ATTR_VLEN+1];
  int statelen;
  uint8_t classbuf[RADIUS_ATTR_VLEN+1];
  int classlen;

  /* Radius proxy stuff */
  /* Parameters are initialised whenever a radius proxy request is received */
  /* Only one outstanding request allowed at a time */
  int radiuswait;                /* Radius request in progres */
  struct sockaddr_in radiuspeer; /* Where to send reply */
  uint8_t radiusid;              /* ID to reply with */
  uint8_t authenticator[RADIUS_AUTHLEN];
  int authtype; /* TODO */
  char proxyuser[USERNAMESIZE];     /* Unauthenticated user: */
  uint8_t proxyuserlen;             /* Length of unauthenticated user */
  uint32_t proxynasip;              /* Set by access request */
  uint32_t proxynasport;            /* Set by access request */
  uint8_t proxyhismac[DHCP_ETH_ALEN];    /* His MAC address */
  uint8_t proxyourmac[DHCP_ETH_ALEN];    /* Our MAC address */

  /* Parameters for radius accounting */
  /* These parameters are set when an access accept is sent back to the
     NAS */
  int authenticated;           /* 1 if user was authenticated */  
  char user[USERNAMESIZE];     /* User: */
  uint8_t userlen;             /* Length of user */
  uint32_t nasip;              /* Set by access request */
  uint32_t nasport;            /* Set by access request */
  uint8_t hismac[DHCP_ETH_ALEN];    /* His MAC address */
  uint8_t ourmac[DHCP_ETH_ALEN];    /* Our MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in_addr hisip;        /* Client IP address */
  struct in_addr reqip;        /* IP requested by client */
  uint16_t mtu;
  
  /* Accounting */
  struct timeval start_time;
  struct timeval interim_time;
  uint32_t input_packets;
  uint32_t output_packets;
  uint64_t input_octets;
  uint64_t output_octets;
  uint32_t terminate_cause;
  uint32_t session_id;

  /* Information for each connection */
  struct in_addr net;
  struct in_addr mask;
  struct in_addr dns1;
  struct in_addr dns2;
  struct timeval last_time; /* Last time a packet was received or sent */

#ifdef LEAKY_BUCKET
  /* Leaky bucket */
  uint32_t bucketup;
  uint32_t bucketdown;
  uint32_t bucketupsize;
  uint32_t bucketdownsize;
#endif

  /* UAM information */
  uint8_t uamchal[REDIR_MD5LEN];
  int uamtime;
  char userurl[USERURLSIZE];
  int uamabort;
};

extern struct app_conn_t *firstfreeconn; /* First free in linked list */
extern struct app_conn_t *lastfreeconn;  /* Last free in linked list */
extern struct app_conn_t *firstusedconn; /* First used in linked list */
extern struct app_conn_t *lastusedconn;  /* Last used in linked list */

extern struct radius_t *radius;          /* Radius client instance */
extern struct dhcp_t *dhcp;              /* DHCP instance */

int printstatus(struct app_conn_t *appconn);

#endif /*_CHILLI_H */
