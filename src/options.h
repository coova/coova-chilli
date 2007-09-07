/* 
 *
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2006 PicoPoint B.V.
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
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

#ifndef _OPTIONS_H
#define _OPTIONS_H

#define IPADDRLEN 256
#define IDLETIME  10  /* Idletime between each select */

#define MAX_PASS_THROUGHS 256 /* Max number of allowed UAM pass-throughs */

#define UAMSERVER_MAX 8

#define MACOK_MAX 16


#include "garden.h"

struct options_t {
  int initialized;
  int foreground;
  int debug;
  /* conf */
  int interval;
  char *pidfile;
  char *statedir;

  int usetap;

  /* TUN parameters */
  struct in_addr net;            /* Network IP address */
  char netc[IPADDRLEN];
  struct in_addr mask;           /* Network mask */
  char maskc[IPADDRLEN];

  char *tundev;
  char *dynip;                   /* Dynamic IP address pool */
  char *statip;                  /* Static IP address pool */
  int allowdyn;                  /* Allow dynamic address allocation */
  int allowstat;                 /* Allow static address allocation */
  struct in_addr dns1;           /* Primary DNS server IP address */
  struct in_addr dns2;           /* Secondary DNS server IP address */
  char *domain;                  /* Domain to use for DNS lookups */
  char* ipup;                    /* Script to run after link-up */
  char* ipdown;                  /* Script to run after link-down */
  char* conup;                   /* Script to run after session/connection-up */
  char* condown;                 /* Script to run after session/connection-down */
  int txqlen;

  /* Radius parameters */
  struct in_addr radiuslisten;   /* IP address to listen to */
  struct in_addr radiusserver1;  /* IP address of radius server 1 */
  struct in_addr radiusserver2;  /* IP address of radius server 2 */
  uint16_t radiusauthport;       /* Authentication UDP port */
  uint16_t radiusacctport;       /* Accounting UDP port */
  char* radiussecret;            /* Radius shared secret */
  char* radiusnasid;             /* Radius NAS-Identifier */
  char* radiuslocationid;        /* WISPr location ID */
  char* radiuslocationname;      /* WISPr location name */
  char* locationname;            /* Location name */
  int radiusnasporttype;         /* NAS-Port-Type */
  uint16_t coaport;              /* UDP port to listen to */
  int coanoipcheck;              /* Allow disconnect from any IP */
  int logfacility;

  /* Radius proxy parameters */
  struct in_addr proxylisten;    /* IP address to listen to */
  int proxyport;                 /* UDP port to listen to */
  struct in_addr proxyaddr;      /* IP address of proxy client(s) */
  struct in_addr proxymask;      /* IP mask of proxy client(s) */
  char* proxysecret;             /* Proxy shared secret */

  struct in_addr postauth_proxyip;  /* IP address to proxy http to */
  int postauth_proxyport;           /* TCP port to proxy to */

  /* DHCP parameters */
  char* dhcpif;                 /* Interface: eth0 */
  unsigned char dhcpmac[DHCP_ETH_ALEN]; /* Interface MAC address */
  int dhcpusemac;               /* Use given MAC or interface default */
  struct in_addr dhcplisten;     /* IP address to listen to */
  int lease;                     /* DHCP lease time */
  int dhcpstart;
  int dhcpend;

  /* EAPOL parameters */
  int eapolenable;               /* Use eapol */

  int swapoctets;
  int usestatusfile;
  int chillixml;

  int pap_always_ok;
  int acct_update;

  /* UAM parameters */
  struct in_addr uamserver[UAMSERVER_MAX]; /* IP address of UAM server */
  int uamserverlen;              /* Number of UAM servers */
  int uamserverport;             /* Port of UAM server */
  char* uamsecret;               /* Shared secret */
  char* uamurl;                  /* URL of authentication server */
  char* uamhomepage;             /* URL of redirection homepage */
  char* wisprlogin;              /* Specific WISPr login url */
  int uamhomepageport;		 /* Port of redirection homepage */
  int no_uamsuccess;             /* Do not send redirect back to UAM on success */
  int no_uamwispr;               /* Do not have ChilliSpot return WISPr blocks */

  struct in_addr uamlisten;      /* IP address of local authentication */
  int uamport;                   /* TCP port to listen to */
  int uamuiport;                 /* TCP port to listen to */

  struct in_addr uamlogout;      /* IP address of HTTP auto-logout */

  int uamanydns;                 /* Allow any dns server */
  int uamanyip;                  /* Allow any ip address */
  int dnsparanoia;               /* Filter DNS for questionable content (dns tunnels) */

  pass_through pass_throughs[MAX_PASS_THROUGHS];
  size_t num_pass_throughs;

  char** uamdomains;

  /* MAC Authentication */
  int macauth;                   /* Use MAC authentication */
  unsigned char macok[MACOK_MAX][DHCP_ETH_ALEN]; /* Allowed MACs */
  int macoklen;                   /* Number of MAC addresses */
  char* macsuffix;               /* Suffix to add to MAC address */
  char* macpasswd;               /* Password to use for MAC authentication */  
  int macallowlocal;             /* Do not use RADIUS for authenticating the macallowed */

  int wpaguests; /* Allow WPS "Guest" access */
  int openidauth; /* Allow OpenID authentication */

  unsigned long defsessiontimeout;
  unsigned int defidletimeout;

  /* local content */
  char *wwwdir;
  char *wwwbin;
  char *uamui;
  char *localusers;

  /* Admin RADIUS Authentication & Configuration */
  char *adminuser;
  char *adminpasswd;

  /* Location-awareness */
  char *ssid;
  char *nasmac;
  char *nasip;

  /* Command-Socket */
  char *cmdsocket;
};

extern struct options_t options;

int option_aton(struct in_addr *addr, struct in_addr *mask, char *pool, int number);
int process_options(int argc, char **argv, int minimal);
void reprocess_options(int argc, char **argv);

#endif /*_OPTIONS_H */
