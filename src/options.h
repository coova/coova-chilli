/* -*- mode: c; c-basic-offset: 2 -*- */
/* 
 * Copyright (C) 2007-2013 David Bird (Coova Technologies) <support@coova.com>
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
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
  char *binconfig;
  char *ethers;

  /* TUN parameters */
  struct in_addr net;            /* Network IP address */
  char netc[OPT_IPADDRLEN];

  struct in_addr mask;           /* Network mask */
  char maskc[OPT_IPADDRLEN];

  char * tundev;
  char * dynip;                  /* Dynamic IP address pool */
  char * statip;                 /* Static IP address pool */
#ifdef ENABLE_UAMANYIP
  int autostatip;                /* Automatically assign "Static" IP addresses */
  struct in_addr uamnatanyipex_addr; /* Exclude a given subnet addres from uamnatanyip */
  struct in_addr uamnatanyipex_mask; /* Exclude a given subnet mask from uamnatanyip */
  struct in_addr uamanyipex_addr; /* Exclude a given subnet addres from uamanyip */
  struct in_addr uamanyipex_mask; /* Exclude a given subnet mask from uamanyip */
#endif
  struct in_addr dns1;           /* Primary DNS server IP address */
  struct in_addr dns2;           /* Secondary DNS server IP address */
  char * domain;                 /* Domain to use for DNS lookups */
  char * ipup;                   /* Script to run after link-up */
  char * ipdown;                 /* Script to run after link-down */
  char * conup;                  /* Script to run after session/connection-up */
  char * condown;                /* Script to run after session/connection-down */
  char * macup;
  char * macdown;
  int txqlen;

#ifdef USING_MMAP
  int ringsize;
#endif

#ifdef ENABLE_IPV6
  struct in6_addr dns1_v6;
  struct in6_addr dns2_v6;
  struct in6_addr v6prefix;
#endif

  int sndbuf;
  int rcvbuf;

  /* Radius parameters */
  struct in_addr radiuslisten;   /* IP address to listen to */

  struct in_addr radiusserver1;  /* IP address of radius server 1 */
  struct in_addr radiusserver2;  /* IP address of radius server 2 */

  char* radiussecret;            /* Radius shared secret */

#ifdef ENABLE_LARGELIMITS
  struct in_addr radiusacctserver1; 
  struct in_addr radiusacctserver2; 
  struct in_addr radiusadmserver1;  
  struct in_addr radiusadmserver2;  
  char* radiusacctsecret;
  char* radiusadmsecret;
#endif

  uint16_t radiusauthport;       /* Authentication UDP port */
  uint16_t radiusacctport;       /* Accounting UDP port */
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

#ifdef ENABLE_RADPROXY
  /* Radius proxy parameters */
  int proxyport;                 /* UDP port to listen to */
  struct in_addr proxylisten;    /* IP address to listen to */
  struct in_addr proxyaddr;      /* IP address of proxy client(s) */
  struct in_addr proxymask;      /* IP mask of proxy client(s) */
  char* proxysecret;             /* Proxy shared secret */
#endif

  struct in_addr postauth_proxyip;  /* IP address to proxy http to */
  int postauth_proxyport;           /* TCP port to proxy to */

  /* DHCP parameters */
  char *dhcpif;                  /* Interface: eth1 */
  char *routeif;                 /* Interface: eth0 (optional) */
  uint8_t dhcpmac[PKT_ETH_ALEN]; /* Interface MAC address */
  struct in_addr dhcplisten;     /* IP address to listen to */
  int lease;                     /* DHCP lease time */
  int leaseplus;                 /* DHCP lease grace period */
  int dhcpstart;
  int dhcpend;

#ifdef ENABLE_MULTILAN
#define MAX_MOREIF (MAX_RAWIF-1)
  struct {
    char *dhcpif;
    char *vlan;
  } moreif[MAX_MOREIF];
#endif

  int childmax;

  uint8_t peerid;
  char *peerkey;

  /* XXX */
  uint8_t nexthop[PKT_ETH_ALEN];
#ifdef ENABLE_NETNAT
  struct in_addr natip;
#endif

  uint16_t mtu;                  /* Max MTU */

  struct in_addr dhcprelayip;    /* IP address of DHCP relay header (default to uamlisten) */
  struct in_addr dhcpgwip;       /* IP address of DHCP gateway to relay to */
  uint16_t dhcpgwport;           /* Port of DHCP gateway to relay to */
  uint16_t tcpwin;               /* TCP Window (zero to leave unchanged) */
  uint16_t tcpmss;               /* TCP Maximum Segment Size (zero to leave unchanged) */

  /* UAM parameters */
  char* uamsecret;               /* Shared secret */
  char* uamurl;                  /* URL of authentication server */
  char* uamaaaurl;               /* URL to use for HTTP based AAA */
  char* uamhomepage;             /* URL of redirection homepage */
  char* wisprlogin;              /* Specific WISPr login url */
  char* usestatusfile;           /* Specific status file to use */

  struct in_addr uamlisten;      /* IP address of local authentication */
  int uamport;                   /* TCP port to listen to */
#ifdef ENABLE_UAMUIPORT
  int uamuiport;                 /* TCP port to listen to */
#endif
  int max_clients;               /* Max subscriber/clients */
  int dhcphashsize;              /* DHCP MAC Hash table size */
  int radiusqsize;               /* Size of RADIUS queue, 0 for default */

  struct in_addr uamlogout;      /* IP address of HTTP auto-logout */
  struct in_addr uamalias;       /* IP address of UAM Alias */
  char *uamaliasname;            /* Simple hostname (no dots) DNS name for uamalias */
  char *uamhostname;             /* Simple hostname (no dots) DNS name for uamlisten */

#ifdef ENABLE_FORCEDNS
  struct in_addr forcedns1_addr;  /* IP address to force DNS to */
  struct in_addr forcedns2_addr;  /* IP address to force DNS to */
  uint16_t forcedns1_port;        /* Port to force DNS to */
  uint16_t forcedns2_port;        /* Port to force DNS to */
#endif

  /* booleans */
  uint8_t layer3;                   /* Layer3 only support */
  unsigned int allowdyn:1;               /* Allow dynamic address allocation */
  unsigned int allowstat:1;              /* Allow static address allocation */
  unsigned int dhcpusemac:1;             /* Use given MAC or interface default */
  unsigned int noc2c:1;
  unsigned int framedservice:1;
  unsigned int usetap:1;
  unsigned int noarpentries:1;
  unsigned int eapolenable:1;            /* Use eapol */
  unsigned int swapoctets:1;
  unsigned int chillixml:1;
  unsigned int pap_always_ok:1;          /* Obsolete */
  unsigned int mschapv2:1;               /* Use and support MSCHAPv2 */
  unsigned int uamanydns:1;              /* Allow any dns server */
#ifdef ENABLE_UAMANYIP
  unsigned int uamanyip:1;               /* Allow any ip address */
  unsigned int uamnatanyip:1;            /* Provide NAT for Any IP clients */
#endif
  unsigned int dnsparanoia:1;            /* Filter DNS for questionable content (dns tunnels) */
  unsigned int no_wispr1:1;              /* Do not offer WISPr 1.0 XML */
  unsigned int no_wispr2:1;              /* Do not offer WISPr 2.0 XML */
  unsigned int acct_update:1;            /* Allow for session parameter updates in accounting response */
  unsigned int wpaguests:1;              /* Allow WPS "Guest" access */
  unsigned int openidauth:1;             /* Allow OpenID authentication */
  unsigned int macauth:1;                /* Use MAC authentication */
  unsigned int macreauth:1;              /* Use MAC re-authentication on /prelogin */
  unsigned int macauthdeny:1;            /* Deny any access to those given Access-Reject */
  unsigned int macallowlocal:1;          /* Do not use RADIUS for authenticating the macallowed */
  unsigned int radiusoriginalurl:1;      /* Send ChilliSpot-OriginalURL in AccessRequest */
  unsigned int dhcpradius:1;             /* Send certain DHCP options in RADIUS attributes */
  unsigned int has_nexthop:1;            /* Has a nexthop entry */
  unsigned int dhcp_broadcast:1;         /* always broadcast DHCP (when not relaying) */
  unsigned int seskeepalive:1;           /* Keep sessions alive during shutdown */
  unsigned int strictmacauth:1;          /* Be strict about DHCP macauth (don't reply DHCP until we get RADIUS) */
  unsigned int strictdhcp:1;             /* Be strict about DHCP allocating from dyn-pool only */
  unsigned int dhcpmacset:1;             /* Set the dhcpif interface with the dhcpmac */
  unsigned int uamallowpost:1;           /* Set to true if the UAMPORT is allowed to access a POST */
  unsigned int redir:1;                  /* Launch redir sub-process instead of forking */
  unsigned int redirurl:1;               /* Send redirection URL in UAM query string instead of HTTP redirect */
  unsigned int redirssl:1;               /* Enable redirection of SSL/HTTPS port (requires SSL support) */
  unsigned int uamuissl:1;               /* Enable SSL/HTTPS on uamuiport (requires SSL support) */
  unsigned int domaindnslocal:1;         /* Wildcard option to consider all hostnames *.domain local */
  unsigned int radsec:1;                 /* Use RadSec tunneling */
  unsigned int noradallow:1;             /* Authorize all sessions when RADIUS is not available */
  unsigned int redirdnsreq:1;
  unsigned int routeonetone:1;
  unsigned int statusfilesave:1;
  unsigned int dhcpnotidle:1;
  unsigned int uamauthedallowed:1;
  unsigned int postauth_proxyssl:1;

#ifdef USING_MMAP
  uint8_t mmapring:1;
#endif

#ifdef ENABLE_IPV6
  unsigned int ipv6:1;
  unsigned int ipv6only:1;
  unsigned int ipv6to4:1;
  unsigned int ipv4to6:1;
#endif

#ifdef ENABLE_LEAKYBUCKET
  unsigned int scalewin:1;
#endif

#ifdef HAVE_PATRICIA
  uint8_t patricia:1;
#endif

#ifdef ENABLE_GARDENACCOUNTING
  uint8_t nousergardendata:1;
  uint8_t uamgardendata:1;
  uint8_t uamotherdata:1;
#endif

#ifdef ENABLE_IEEE8021Q
  unsigned int ieee8021q:1;              /* check for VLAN tags */
  unsigned int ieee8021q_only:1;              /* check for VLAN tags */
#endif
#ifdef ENABLE_RADPROXY
  unsigned int proxymacaccept:1;         /* Auto-accept non-EAP requests on proxy port */
  unsigned int proxyonacct:1;
#endif
#ifdef ENABLE_PROXYVSA
  uint8_t vlanlocation:1;
  uint8_t location_stop_start:1;
  uint8_t location_copy_called:1;
  uint8_t location_immediate_update:1;
  uint8_t location_option_82:1;
#endif
#ifdef ENABLE_REDIRINJECT
  uint8_t inject_wispr:1;
#endif
  /* */
#ifdef EX_OPTIONS
#include EX_OPTIONS
#endif

#ifdef ENABLE_REDIRINJECT
  char *inject;
  char *inject_ext;
#endif

#ifdef ENABLE_EXTADMVSA
#define EXTADMVSA_ATTR_CNT 4
  struct {
    uint32_t attr_vsa;
    uint8_t attr;
    char data[128];
    char script[128];
  } extadmvsa[EXTADMVSA_ATTR_CNT];
#endif

  pass_through pass_throughs[MAX_PASS_THROUGHS];
  uint32_t num_pass_throughs;

#ifdef ENABLE_AUTHEDALLOWED
  pass_through authed_pass_throughs[MAX_PASS_THROUGHS];
  uint32_t num_authed_pass_throughs;
#endif

#ifdef ENABLE_CHILLIREDIR
  regex_pass_through regex_pass_throughs[MAX_REGEX_PASS_THROUGHS];
  uint32_t regex_num_pass_throughs;
#endif

#ifdef ENABLE_LAYER3
  pass_through ipsrc_pass_throughs[MAX_IPSRC_PASS_THROUGHS];
  uint32_t ipsrc_num_pass_throughs;
#endif

  char* uamdomains[MAX_UAM_DOMAINS];
  int uamdomain_ttl;

  /* MAC Authentication */
  uint8_t macok[MACOK_MAX][PKT_ETH_ALEN]; /* Allowed MACs */
  int macoklen;                   /* Number of MAC addresses */
  char* macsuffix;               /* Suffix to add to MAC address */
  char* macpasswd;               /* Password to use for MAC authentication */  

  uint64_t defsessiontimeout;
  uint64_t defbandwidthmaxdown;
  uint64_t defbandwidthmaxup;
  uint32_t defidletimeout;
  uint16_t definteriminterval;

  uint32_t challengetimeout;
  uint32_t challengetimeout2;

#ifdef ENABLE_PROXYVSA
#define PROXYVSA_ATTR_CNT 4
  struct {
    uint32_t attr_vsa;
    uint8_t attr;
  } proxy_loc[PROXYVSA_ATTR_CNT];
  char * locationupdate;
#endif

#ifdef HAVE_SSL
  char *sslkeyfile;
  char *sslkeypass;
  char *sslcertfile;
  char *sslcafile;
#endif

  /* local content */
  char *wwwdir;
  char *wwwbin;
  char *uamui;
  char *localusers;

  /* Admin RADIUS Authentication & Configuration */
  char *adminuser;
  char *adminpasswd;
  char *adminupdatefile;
  char *rtmonfile;

  /* Location-awareness */
  char *ssid;
  char *vlan;
  char *nasmac;
  char *nasip;

#ifdef ENABLE_DHCPOPT
  uint8_t dhcp_options[512];
  int dhcp_options_len;
#endif

#ifdef ENABLE_DNSLOG
  char *dnslog;
#endif

#ifdef ENABLE_IPWHITELIST
  char *ipwhitelist;
#endif

#ifdef ENABLE_UAMDOMAINFILE
  char *uamdomainfile;
#endif

  /* Command-Socket */
  char *cmdsocket;
  uint16_t cmdsocketport;

#ifdef ENABLE_IEEE8021Q
  char * vlanupdate;
#endif

#ifdef ENABLE_LEAKYBUCKET
  uint32_t bwbucketupsize;
  uint32_t bwbucketdnsize;
  uint32_t bwbucketminsize;
#endif

#ifdef USING_IPC_UNIX
  char *unixipc;
#endif

#ifdef ENABLE_WPAD
  char *wpadpacfile;
#endif

#ifdef HAVE_NETFILTER_COOVA
  char *kname;
#endif

#ifdef ENABLE_MODULES
#define MAX_MODULES 4
  struct {
    char name[32];
    char conf[128];
    void *ctx;
  } modules[MAX_MODULES];
  char *moddir;
#endif

  char * _data; /* actual data buffer for loaded options */
};

int options_mkdir(char *path);
int options_fromfd(int fd, bstring bt);
int options_binload(char *file);
int option_aton(struct in_addr *addr, struct in_addr *mask, char *pool, int number);
int process_options(int argc, char **argv, int minimal);
void reprocess_options(int argc, char **argv);
int reload_options(int argc, char **argv);
int options_save(char *file, bstring bt);
void options_init();
void options_destroy();
void options_cleanup();

#ifndef MAIN_FILE /* all main() files must implement _options */
extern struct options_t _options;
#endif


#endif /*_OPTIONS_H */
