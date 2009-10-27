/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
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

#ifndef _CHILLI_H
#define _CHILLI_H

/*#define XXX_IO_DAEMON 1*/

/* Authtype defs */
#define CHAP_DIGEST_MD5   0x05
#define CHAP_MICROSOFT    0x80
#define CHAP_MICROSOFT_V2 0x81
#define PAP_PASSWORD       256
#define EAP_MESSAGE        257

#define MPPE_KEYSIZE  16
#define NT_KEYSIZE    16


#define DNPROT_NULL       1
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
  
  struct app_conn_t *next;    /* Next in linked list. 0: Last */
  struct app_conn_t *prev;    /* Previous in linked list. 0: First */

  /* Pointers to protocol handlers */
  void *uplink;                  /* Uplink network interface (Internet) */
  void *dnlink;                  /* Downlink network interface (Wireless) */

  char is_adminsession;

  /* Management of connections */
  int inuse;
  int unit;
  int dnprot;                    /* Downlink protocol */

#if(0)
#define s_params  params[0]
#define ss_params params[1]
#define s_state   state[0]
#define ss_state  state[1]
  struct session_params params[2];        /* Session parameters */
  struct session_state  state[2];         /* Session state */
  char has_subsession;
#endif

  struct session_params s_params;         /* Session parameters */
  struct session_state  s_state;          /* Session state */

  /* Radius authentication stuff */
  /* Parameters are initialised whenever a reply to an access request
     is received. */
  uint8_t chal[EAP_LEN];         /* EAP challenge */
  size_t challen;                /* Length of EAP challenge */
  uint8_t sendkey[RADIUS_ATTR_VLEN];
  uint8_t recvkey[RADIUS_ATTR_VLEN];
  uint8_t lmntkeys[RADIUS_MPPEKEYSSIZE];
  size_t sendlen;
  size_t recvlen;
  size_t lmntlen;
  uint32_t policy;
  uint32_t types;
  uint8_t ms2succ[MS2SUCCSIZE];
  size_t ms2succlen;

  /* Radius proxy stuff */
  /* Parameters are initialised whenever a radius proxy request is received */
  /* Only one outstanding request allowed at a time */
  int radiuswait;                /* Radius request in progres */
  struct sockaddr_in radiuspeer; /* Where to send reply */
  uint8_t radiusid;              /* ID to reply with */
  uint8_t authenticator[RADIUS_AUTHLEN];
  int authtype; /* TODO */

  /* Parameters for radius accounting */
  /* These parameters are set when an access accept is sent back to the
     NAS */

  uint32_t nasip;              /* Set by access request */
  uint32_t nasport;            /* Set by access request */
  uint8_t hismac[PKT_ETH_ALEN];/* His MAC address */
  struct in_addr ourip;        /* IP address to listen to */
  struct in_addr hisip;        /* Client IP address */
  struct in_addr reqip;        /* IP requested by client */
  struct in_addr natip;
  uint16_t mtu;

  /* Information for each connection */
  struct in_addr net;
  struct in_addr mask;
  struct in_addr dns1;
  struct in_addr dns2;

  /* UAM information */
  char uamabort; /* should be bit options */
  char uamexit;
};

extern struct app_conn_t *firstfreeconn; /* First free in linked list */
extern struct app_conn_t *lastfreeconn;  /* Last free in linked list */
extern struct app_conn_t *firstusedconn; /* First used in linked list */
extern struct app_conn_t *lastusedconn;  /* Last used in linked list */

extern struct radius_t *radius;          /* Radius client instance */
extern struct dhcp_t *dhcp;              /* DHCP instance */
extern struct tun_t *tun;                /* TUN/TAP instance */

#ifdef ENABLE_STATFILE
int printstatus();
int loadstatus();
#endif

int terminate_appconn(struct app_conn_t *appconn, int terminate_cause);
void config_radius_session(struct session_params *params, 
			   struct radius_packet_t *pack, 
			   struct dhcp_conn_t *dhcpconn,
			   int reconfig);
int cmdsock_init();

time_t mainclock_now();
int mainclock_diff(time_t past);
uint32_t mainclock_diffu(time_t past);

#endif /*_CHILLI_H */
