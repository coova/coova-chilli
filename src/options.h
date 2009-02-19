/* 
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2006 PicoPoint B.V.
 * Copyright (c) 2006-2009 David Bird <david@coova.com>
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

#include "pkt.h"
#include "garden.h"

struct options_t {
  int initialized;
  int foreground;
  int debug;
  /* conf */
  uid_t uid;
  gid_t gid;
  int interval;
  char *pidfile;
  char *statedir;

  /* TUN parameters */
  struct in_addr net;            /* Network IP address */
  char netc[OPT_IPADDRLEN];
  struct in_addr mask;           /* Network mask */
  char maskc[OPT_IPADDRLEN];

  char * tundev;
  char * dynip;                  /* Dynamic IP address pool */
  char * statip;                 /* Static IP address pool */
  int autostatip;                /* Automatically assign "Static" IP addresses */
  int allowdyn;                  /* Allow dynamic address allocation */
  int allowstat;                 /* Allow static address allocation */
  struct in_addr dns1;           /* Primary DNS server IP address */
  struct in_addr dns2;           /* Secondary DNS server IP address */
  char * domain;                 /* Domain to use for DNS lookups */
  char * ipup;                   /* Script to run after link-up */
  char * ipdown;                 /* Script to run after link-down */
  char * conup;                  /* Script to run after session/connection-up */
  char * condown;                /* Script to run after session/connection-down */
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
  int radiustimeout;             /* Retry timeout in milli seconds */
  int radiusretry;               /* Total amount of retries */
  int radiusretrysec;            /* Amount of retries after we switch to secondary */

  /* Radius proxy parameters */
  struct in_addr proxylisten;    /* IP address to listen to */
  int proxyport;                 /* UDP port to listen to */
  struct in_addr proxyaddr;      /* IP address of proxy client(s) */
  struct in_addr proxymask;      /* IP mask of proxy client(s) */
  char* proxysecret;             /* Proxy shared secret */

  struct in_addr postauth_proxyip;  /* IP address to proxy http to */
  int postauth_proxyport;           /* TCP port to proxy to */

  /* DHCP parameters */
  char *dhcpif;                 /* Interface: eth1 */
  char *routeif;                /* Interface: eth0 (optional) */
  unsigned char dhcpmac[PKT_ETH_ALEN]; /* Interface MAC address */
  int dhcpusemac;                /* Use given MAC or interface default */
  struct in_addr dhcplisten;     /* IP address to listen to */
  int lease;                     /* DHCP lease time */
  int dhcpstart;
  int dhcpend;

  uint16_t mtu;                  /* Max MTU */

  struct in_addr dhcprelayip;    /* IP address of DHCP relay header (default to uamlisten) */
  struct in_addr dhcpgwip;       /* IP address of DHCP gateway to relay to */
  uint16_t dhcpgwport;           /* Port of DHCP gateway to relay to */


  /* UAM parameters */
  struct in_addr uamserver[UAMSERVER_MAX]; /* IP address of UAM server */
  int uamserverlen;              /* Number of UAM servers */
  int uamserverport;             /* Port of UAM server */
  char* uamsecret;               /* Shared secret */
  char* uamurl;                  /* URL of authentication server */
  char* uamhomepage;             /* URL of redirection homepage */
  char* wisprlogin;              /* Specific WISPr login url */
  int uamhomepageport;		 /* Port of redirection homepage */

  struct in_addr uamlisten;      /* IP address of local authentication */
  int uamport;                   /* TCP port to listen to */
  int uamuiport;                 /* TCP port to listen to */

  struct in_addr uamlogout;      /* IP address of HTTP auto-logout */


  /* booleans */
  uint8_t noc2c:1;
  uint8_t framedservice:1;
  uint8_t usetap:1;
  uint8_t eapolenable:1;            /* Use eapol */
  uint8_t swapoctets:1;
  uint8_t usestatusfile:1;
  uint8_t chillixml:1;
  uint8_t pap_always_ok:1;
  uint8_t uamanydns:1;              /* Allow any dns server */
  uint8_t uamanyip:1;               /* Allow any ip address */
  uint8_t dnsparanoia:1;            /* Filter DNS for questionable content (dns tunnels) */
  uint8_t no_uamsuccess:1;          /* Do not send redirect back to UAM on success */
  uint8_t no_uamwispr:1;            /* Do not have ChilliSpot return WISPr blocks */
  uint8_t acct_update:1;
  uint8_t wpaguests:1;              /* Allow WPS "Guest" access */
  uint8_t openidauth:1;             /* Allow OpenID authentication */
  uint8_t macauth:1;                /* Use MAC authentication */
  uint8_t macreauth:1;              /* Use MAC re-authentication on /prelogin */
  uint8_t macauthdeny:1;            /* Deny any access to those given Access-Reject */
  uint8_t macallowlocal:1;          /* Do not use RADIUS for authenticating the macallowed */
  uint8_t radiusoriginalurl:1;      /* Send ChilliSpot-OriginalURL in AccessRequest */
  uint8_t dhcpradius:1;             /* Send certain DHCP options in RADIUS attributes */
  /* */

  pass_through pass_throughs[MAX_PASS_THROUGHS];
  size_t num_pass_throughs;

  char** uamdomains;

  /* MAC Authentication */
  unsigned char macok[MACOK_MAX][PKT_ETH_ALEN]; /* Allowed MACs */
  int macoklen;                   /* Number of MAC addresses */
  char* macsuffix;               /* Suffix to add to MAC address */
  char* macpasswd;               /* Password to use for MAC authentication */  

  unsigned long defsessiontimeout;
  unsigned int defbandwidthmaxdown;
  unsigned int defbandwidthmaxup;
  unsigned int defidletimeout;
  unsigned short definteriminterval;

  unsigned int challengetimeout;
  unsigned int challengetimeout2;

  /* local content */
  char *wwwdir;
  char *wwwbin;
  char *uamui;
  char *localusers;

  /* Admin RADIUS Authentication & Configuration */
  char *adminuser;
  char *adminpasswd;
  char *adminupdatefile;

  /* Location-awareness */
  char *ssid;
  char *nasmac;
  char *nasip;

  /* Command-Socket */
  char *cmdsocket;
  
  char **extra_argv;
  int extra_argc;
};

extern struct options_t options;

int option_aton(struct in_addr *addr, struct in_addr *mask, char *pool, int number);
int process_options(int argc, char **argv, int minimal);
void reprocess_options(int argc, char **argv);

#endif /*_OPTIONS_H */
