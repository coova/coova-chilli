/* 
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

#include "system.h"
#include "syserr.h"
#include "cmdline.h"
#include "dhcp.h"
#include "radius.h"
#include "radius_chillispot.h"
#include "radius_wispr.h"
#include "redir.h"
#include "chilli.h"
#include "options.h"
#include "cmdsock.h"


/* Extract domain name and port from URL */
static int get_namepart(char *src, char *host, int hostsize, int *port) {
  char *slashslash = NULL;
  char *slash = NULL;
  char *colon = NULL;
  int hostlen;
  
  *port = 0;

  if (!memcmp(src, "http://", 7)) {
    *port = DHCP_HTTP;
  }
  else   if (!memcmp(src, "https://", 8)) {
    *port = DHCP_HTTPS;
  }
  else {
    log_err(0, "URL must start with http:// or https:// %s!", src);
    return -1;
  }
  
  /* The host name must be initiated by "//" and terminated by /, :  or \0 */
  if (!(slashslash = strstr(src, "//"))) {
    log_err(0, "// not found in url: %s!", src);
    return -1;
  }
  slashslash+=2;
  
  slash = strstr(slashslash, "/");
  colon = strstr(slashslash, ":");
  
  if ((slash != NULL) && (colon != NULL) &&
      (slash < colon)) {
    hostlen = slash - slashslash;
  }
  else if ((slash != NULL) && (colon == NULL)) {
    hostlen = slash - slashslash;
  }
  else if (colon != NULL) {
    hostlen = colon - slashslash;
    if (1 != sscanf(colon+1, "%d", port)) {
      log_err(0, "Not able to parse URL port: %s!", src);
      return -1;
    }
  }
  else {
    hostlen = strlen(src);
  }

  if (hostlen > (hostsize-1)) {
    log_err(0, "URL hostname larger than %d: %s!", hostsize-1, src);
    return -1;
  }

  strncpy(host, slashslash, hostsize);
  host[hostlen] = 0;

  return 0;
}


static const char *description = 
  "CoovaChilli - A Wireless LAN Access Point Controller.\n"
  "  For more information on this project, visit: \n"
  "  http://www.coova.org/\n";

static const char *copyright = 
  "Copyright (c) 2003-2005 Mondru AB., 2006-2009 Coova Technologies LLC, and others.\n"
  "Licensed under the Gnu Public License (GPL).\n";

static const char *usage = \
  "Usage: chilli [OPTIONS]...\n";

extern const char *gengetopt_args_info_help[];

static void
options_print_version (void) {
  printf ("%s %s\n", CMDLINE_PARSER_PACKAGE, CMDLINE_PARSER_VERSION);
}

static void
options_print_help (void) {
  int i = 0;
  options_print_version();

  printf("\n%s", description);
  printf("\n%s\n", usage);

  while (gengetopt_args_info_help[i])
    printf("%s\n", gengetopt_args_info_help[i++]);

  printf("\n%s\n", copyright);
}

char *STRDUP(char *s) {
  if (!s) return 0;
  while (isspace(*s)) s++;
  if (!*s) return 0;
  return s;
}

int main(int argc, char **argv) {
  struct gengetopt_args_info args_info;
  struct options_t *opt;
  struct hostent *host;
  char hostname[USERURLSIZE];
  int numargs;
  int ret = -1;

  options_set(opt = (struct options_t *)calloc(1, sizeof(struct options_t)));

  memset(&args_info, 0, sizeof(args_info));

  if (cmdline_parser2(argc, argv, &args_info, 1, 1, 1) != 0) {
    log_err(0, "Failed to parse command line options");
    goto end_processing;
  }

  if (args_info.version_given) {
    options_print_version();
    exit(2);
  }

  if (args_info.help_given) {
    options_print_help();
    exit(2);
  }

  if (cmdline_parser_configfile(args_info.conf_arg ? 
				args_info.conf_arg : 
				DEFCHILLICONF, 
				&args_info, 0, 0, 0)) {
    log_err(0, "Failed to parse configuration file: %s!", 
	    args_info.conf_arg);
    goto end_processing;
  }

  /* Get the system default DNS entries */
  if (res_init()) {
    log_err(0, "Failed to update system DNS settings (res_init()!");
    goto end_processing;
  }

  /* Handle each option */
  opt->initialized = 1;

  if (args_info.debug_flag) 
    opt->debug = args_info.debugfacility_arg;
  else 
    opt->debug = 0;

  /** simple configuration parameters **/
  opt->uid = args_info.uid_arg;
  opt->gid = args_info.gid_arg;
  opt->mtu = args_info.mtu_arg;
  opt->usetap = args_info.usetap_flag;
  opt->foreground = args_info.fg_flag;
  opt->interval = args_info.interval_arg;
  opt->lease = args_info.lease_arg;
  opt->dhcpstart = args_info.dhcpstart_arg;
  opt->dhcpend = args_info.dhcpend_arg;
  opt->eapolenable = args_info.eapolenable_flag;
  opt->swapoctets = args_info.swapoctets_flag;
  opt->logfacility = args_info.logfacility_arg;
  opt->chillixml = args_info.chillixml_flag;
  opt->macauth = args_info.macauth_flag;
  opt->macreauth = args_info.macreauth_flag;
  opt->macauthdeny = args_info.macauthdeny_flag;
  opt->uamport = args_info.uamport_arg;
  opt->uamuiport = args_info.uamuiport_arg;
  opt->macallowlocal = args_info.macallowlocal_flag;
  opt->no_uamwispr = args_info.nouamwispr_flag;
  opt->wpaguests = args_info.wpaguests_flag;
  opt->openidauth = args_info.openidauth_flag;
  opt->challengetimeout = args_info.challengetimeout_arg;
  opt->challengetimeout2 = args_info.challengetimeout2_arg;
  opt->defsessiontimeout = args_info.defsessiontimeout_arg;
  opt->definteriminterval = args_info.definteriminterval_arg;
  opt->defbandwidthmaxdown = args_info.defbandwidthmaxdown_arg;
  opt->defbandwidthmaxup = args_info.defbandwidthmaxup_arg;
  opt->defidletimeout = args_info.defidletimeout_arg;
  opt->radiusnasporttype = args_info.radiusnasporttype_arg;
  opt->radiusauthport = args_info.radiusauthport_arg;
  opt->radiusacctport = args_info.radiusacctport_arg;
  opt->coaport = args_info.coaport_arg;
  opt->coanoipcheck = args_info.coanoipcheck_flag;
  opt->radiustimeout = args_info.radiustimeout_arg;
  opt->radiusretry = args_info.radiusretry_arg;
  opt->radiusretrysec = args_info.radiusretrysec_arg;
  opt->proxyport = args_info.proxyport_arg;
  opt->txqlen = args_info.txqlen_arg;
  opt->postauth_proxyport = args_info.postauthproxyport_arg;
  opt->pap_always_ok = args_info.papalwaysok_flag;
  opt->mschapv2 = args_info.mschapv2_flag;
  opt->acct_update = args_info.acctupdate_flag;
  opt->dhcpradius = args_info.dhcpradius_flag;
  opt->ieee8021q = args_info.ieee8021q_flag;
  opt->dhcp_broadcast = args_info.dhcpbroadcast_flag;
  opt->dhcpgwport = args_info.dhcpgatewayport_arg;
  opt->noc2c = args_info.noc2c_flag;
  opt->tcpwin = args_info.tcpwin_arg;
  opt->tcpmss = args_info.tcpmss_arg;
  opt->max_clients = args_info.maxclients_arg;
  opt->seskeepalive = args_info.seskeepalive_flag;

  if (args_info.dhcpgateway_arg &&
      !inet_aton(args_info.dhcpgateway_arg, &opt->dhcpgwip)) {
    log_err(0, "Invalid DHCP gateway IP address: %s!", args_info.dhcpgateway_arg);
    goto end_processing;
  }

  if (args_info.dhcprelayagent_arg &&
      !inet_aton(args_info.dhcprelayagent_arg, &opt->dhcprelayip)) {
    log_err(0, "Invalid DHCP gateway relay IP address: %s!", args_info.dhcprelayagent_arg);
    goto end_processing;
  }

  opt->dhcpif = STRDUP(args_info.dhcpif_arg);

  if (!args_info.radiussecret_arg) {
    log_err(0, "radiussecret must be specified!");
    goto end_processing;
  }

  if (!args_info.nexthop_arg) {
    memset(opt->nexthop, 0, PKT_ETH_ALEN);
    opt->has_nexthop = 0;
  }
  else {
    unsigned int temp[PKT_ETH_ALEN];
    char macstr[RADIUS_ATTR_VLEN];
    int macstrlen;
    int	i;

    if ((macstrlen = strlen(args_info.nexthop_arg)) >= (RADIUS_ATTR_VLEN-1)) {
      log_err(0, "MAC address too long");
      goto end_processing;
    }

    memcpy(macstr, args_info.nexthop_arg, macstrlen);
    macstr[macstrlen] = 0;

    /* Replace anything but hex with space */
    for (i=0; i<macstrlen; i++) 
      if (!isxdigit(macstr[i])) 
	macstr[i] = 0x20;

    if (sscanf (macstr, "%2x %2x %2x %2x %2x %2x", 
		&temp[0], &temp[1], &temp[2], 
		&temp[3], &temp[4], &temp[5]) != 6) {
      log_err(0, "MAC conversion failed!");
      return -1;
    }
    
    for (i = 0; i < PKT_ETH_ALEN; i++) 
      opt->nexthop[i] = temp[i];

    opt->has_nexthop = 1;
  }

  if (!args_info.dhcpmac_arg) {
    memset(opt->dhcpmac, 0, PKT_ETH_ALEN);
    opt->dhcpusemac  = 0;
  }
  else {
    unsigned int temp[PKT_ETH_ALEN];
    char macstr[RADIUS_ATTR_VLEN];
    int macstrlen;
    int	i;

    if ((macstrlen = strlen(args_info.dhcpmac_arg)) >= (RADIUS_ATTR_VLEN-1)) {
      log_err(0, "MAC address too long");
      goto end_processing;
    }

    memcpy(macstr, args_info.dhcpmac_arg, macstrlen);
    macstr[macstrlen] = 0;

    /* Replace anything but hex with space */
    for (i=0; i<macstrlen; i++) 
      if (!isxdigit(macstr[i])) macstr[i] = 0x20;

    if (sscanf (macstr, "%2x %2x %2x %2x %2x %2x", 
		&temp[0], &temp[1], &temp[2], 
		&temp[3], &temp[4], &temp[5]) != 6) {
      log_err(0, "MAC conversion failed!");
      return -1;
    }
    
    for (i = 0; i < PKT_ETH_ALEN; i++) 
      opt->dhcpmac[i] = temp[i];

    opt->dhcpusemac  = 1;
  }

  if (args_info.net_arg) {
    if (option_aton(&opt->net, &opt->mask, args_info.net_arg, 0)) {
      log_err(0, "Invalid network address: %s!", args_info.net_arg);
      goto end_processing;
    }
    if (!args_info.uamlisten_arg) {
      opt->uamlisten.s_addr = htonl(ntohl(opt->net.s_addr)+1);
    }
    else if (!inet_aton(args_info.uamlisten_arg, &opt->uamlisten)) {
      log_err(0, "Invalid UAM IP address: %s!", args_info.uamlisten_arg);
      goto end_processing;
    }
    if (!args_info.dhcplisten_arg) {
      opt->dhcplisten.s_addr = opt->uamlisten.s_addr;
    }
    else if (!inet_aton(args_info.dhcplisten_arg, &opt->dhcplisten)) {
      log_err(0, "Invalid DHCP IP address: %s!", args_info.dhcplisten_arg);
      goto end_processing;
    }
  }
  else {
    log_err(0, "Network address must be specified ('net' parameter)!");
    goto end_processing;
  }


  log_dbg("DHCP Listen: %s", inet_ntoa(opt->dhcplisten));
  log_dbg("UAM Listen: %s", inet_ntoa(opt->uamlisten));

  if (!args_info.uamserver_arg) {
    log_err(0, "WARNING: No uamserver defiend!");
  }

  if (args_info.uamserver_arg) {
    if (opt->debug & DEBUG_CONF) {
      log_dbg("Uamserver: %s\n", args_info.uamserver_arg);
    }
    memset(opt->uamserver, 0, sizeof(opt->uamserver));
    opt->uamserverlen = 0;
    if (get_namepart(args_info.uamserver_arg, hostname, USERURLSIZE, 
		     &opt->uamserverport)) {
      log_err(0, "Failed to parse uamserver: %s!", args_info.uamserver_arg);
      goto end_processing;
    }
  
    if (!(host = gethostbyname(hostname))) {
      log_err(0, "Could not resolve IP address of uamserver: %s! [%s]", 
	      args_info.uamserver_arg, strerror(errno));
      goto end_processing;
    }
    else {
      int j = 0;
      while (host->h_addr_list[j] != NULL) {
	if (opt->debug & DEBUG_CONF) {
	  log_dbg("Uamserver IP address #%d: %s\n", j,
		 inet_ntoa(*(struct in_addr*) host->h_addr_list[j]));
	}
	if (opt->uamserverlen>=UAMSERVER_MAX) {
	  log_err(0,
		  "Too many IPs in uamserver %s!",
		  args_info.uamserver_arg);
	  goto end_processing;
	}
	else {
	  opt->uamserver[opt->uamserverlen++] = 
	    *((struct in_addr*) host->h_addr_list[j++]);
	}
      }
    }
  }

  if (args_info.uamhomepage_arg) {
    if (get_namepart(args_info.uamhomepage_arg, hostname, USERURLSIZE, 
		     &opt->uamhomepageport)) {
      log_err(0,"Failed to parse uamhomepage: %s!", args_info.uamhomepage_arg);
      goto end_processing;
    }

    if (!(host = gethostbyname(hostname))) {
      log_err(0,"Invalid uamhomepage: %s! [%s]", 
	      args_info.uamhomepage_arg, strerror(errno));
      goto end_processing;
    }
    else {
      int j = 0;
      while (host->h_addr_list[j] != NULL) {
	if (opt->uamserverlen>=UAMSERVER_MAX) {
	  log_err(0,"Too many IPs in uamhomepage %s!",
		  args_info.uamhomepage_arg);
	  goto end_processing;
	}
	else {
	  opt->uamserver[opt->uamserverlen++] = 
	    *((struct in_addr*) host->h_addr_list[j++]);
	}
      }
    }
  }

  opt->uamanydns = args_info.uamanydns_flag;
  opt->uamanyip = args_info.uamanyip_flag;
  opt->uamnatanyip = args_info.uamnatanyip_flag;
  opt->dnsparanoia = args_info.dnsparanoia_flag;
  opt->radiusoriginalurl = args_info.radiusoriginalurl_flag;

  /* pass-throughs */
  memset(opt->pass_throughs, 0, sizeof(opt->pass_throughs));
  opt->num_pass_throughs = 0;

  for (numargs = 0; numargs < args_info.uamallowed_given; ++numargs) {
    pass_throughs_from_string(opt->pass_throughs,
			      MAX_PASS_THROUGHS,
			      &opt->num_pass_throughs,
			      args_info.uamallowed_arg[numargs]);
  }

  for (numargs = 0; numargs < MAX_UAM_DOMAINS; ++numargs) {
    if (opt->uamdomains[numargs])
      free(opt->uamdomains[numargs]);
    opt->uamdomains[numargs] = 0;
  }

  if (args_info.uamdomain_given) {
    for (numargs = 0; numargs < args_info.uamdomain_given && numargs < MAX_UAM_DOMAINS; ++numargs) 
      opt->uamdomains[numargs] = STRDUP(args_info.uamdomain_arg[numargs]);
  }

  opt->allowdyn = 1;
  
  opt->autostatip = args_info.autostatip_arg;
  if (opt->autostatip)
    opt->uamanyip = 1;
  
  if (args_info.nodynip_flag) {
    opt->allowdyn = 0;
  } else {
    if (!args_info.dynip_arg) {
      opt->dynip = STRDUP(args_info.net_arg);
    }
    else {
      struct in_addr addr;
      struct in_addr mask;
      opt->dynip = STRDUP(args_info.dynip_arg);
      if (option_aton(&addr, &mask, opt->dynip, 0)) {
	log_err(0, "Failed to parse dynamic IP address pool!");
	goto end_processing;
      }
    }
  }
  
  /* statip */
  if (args_info.statip_arg) {
    struct in_addr addr;
    struct in_addr mask;
    opt->statip = STRDUP(args_info.statip_arg);
    if (option_aton(&addr, &mask, opt->statip, 0)) {
      log_err(0, "Failed to parse static IP address pool!");
      return -1;
    }
    opt->allowstat = 1;
  } else {
    opt->allowstat = 0;
  }

  if (args_info.dns1_arg) {
    if (!inet_aton(args_info.dns1_arg, &opt->dns1)) {
      log_err(0,"Invalid primary DNS address: %s!", 
	      args_info.dns1_arg);
      goto end_processing;
    }
  }
  else if (_res.nscount >= 1) {
    opt->dns1 = _res.nsaddr_list[0].sin_addr;
  }
  else {
    opt->dns1.s_addr = 0;
  }

  if (args_info.dns2_arg) {
    if (!inet_aton(args_info.dns2_arg, &opt->dns2)) {
      log_err(0,"Invalid secondary DNS address: %s!", 
	      args_info.dns1_arg);
      goto end_processing;
    }
  }
  else if (_res.nscount >= 2) {
    opt->dns2 = _res.nsaddr_list[1].sin_addr;
  }
  else {
    opt->dns2.s_addr = opt->dns1.s_addr;
  }


  /* If no listen option is specified listen to any local port    */
  /* Do hostname lookup to translate hostname to IP address       */
  if (args_info.radiuslisten_arg) {
    if (!(host = gethostbyname(args_info.radiuslisten_arg))) {
      log_err(0, "Invalid listening address: %s! [%s]", 
	      args_info.radiuslisten_arg, strerror(errno));
      goto end_processing;
    }
    else {
      memcpy(&opt->radiuslisten.s_addr, host->h_addr, host->h_length);
    }
  }
  else {
    opt->radiuslisten.s_addr = htonl(INADDR_ANY);
  }

  if (args_info.uamlogoutip_arg) {
    if (!(host = gethostbyname(args_info.uamlogoutip_arg))) {
      log_warn(0, "Invalid uamlogoutup address: %s! [%s]", 
	       args_info.uamlogoutip_arg, strerror(errno));
    }
    else {
      memcpy(&opt->uamlogout.s_addr, host->h_addr, host->h_length);
    }
  }

  if (args_info.postauthproxy_arg) {
    if (!(host = gethostbyname(args_info.postauthproxy_arg))) {
      log_warn(0, "Invalid postauthproxy address: %s! [%s]", 
	       args_info.postauthproxy_arg, strerror(errno));
    }
    else {
      memcpy(&opt->postauth_proxyip.s_addr, host->h_addr, host->h_length);
    }
  }

  /* If no option is specified terminate                          */
  /* Do hostname lookup to translate hostname to IP address       */
  if (args_info.radiusserver1_arg) {
    if (!(host = gethostbyname(args_info.radiusserver1_arg))) {
      log_err(0, "Invalid radiusserver1 address: %s! [%s]", 
	      args_info.radiusserver1_arg, strerror(errno));
      goto end_processing;
    }
    else {
      memcpy(&opt->radiusserver1.s_addr, host->h_addr, host->h_length);
    }
  }
  else {
    log_err(0,"No radiusserver1 address given!");
    goto end_processing;
  }

  /* radiusserver2 */
  /* If no option is specified terminate                          */
  /* Do hostname lookup to translate hostname to IP address       */
  if (args_info.radiusserver2_arg) {
    if (!(host = gethostbyname(args_info.radiusserver2_arg))) {
      log_err(0, "Invalid radiusserver2 address: %s! [%s]", 
	      args_info.radiusserver2_arg, strerror(errno));
      goto end_processing;
    }
    else {
      memcpy(&opt->radiusserver2.s_addr, host->h_addr, host->h_length);
    }
  }
  else {
    opt->radiusserver2.s_addr = 0;
  }

  /* If no listen option is specified listen to any local port    */
  /* Do hostname lookup to translate hostname to IP address       */
  if (args_info.proxylisten_arg) {
    if (!(host = gethostbyname(args_info.proxylisten_arg))) {
      log_err(0, "Invalid listening address: %s! [%s]", 
	      args_info.proxylisten_arg, strerror(errno));
      goto end_processing;
    }
    else {
      memcpy(&opt->proxylisten.s_addr, host->h_addr, host->h_length);
    }
  }
  else {
    opt->proxylisten.s_addr = htonl(INADDR_ANY);
  }
  
  /* Store proxyclient as in_addr net and mask                       */
  if (args_info.proxyclient_arg) {
    if(option_aton(&opt->proxyaddr, &opt->proxymask, 
		   args_info.proxyclient_arg, 0)) {
      log_err(0,"Invalid proxy client address: %s!", args_info.proxyclient_arg);
      goto end_processing;
    }
  }
  else {
    opt->proxyaddr.s_addr = ~0; /* Let nobody through */
    opt->proxymask.s_addr = 0; 
  }

  memset(opt->macok, 0, sizeof(opt->macok));
  opt->macoklen = 0;
  for (numargs = 0; numargs < args_info.macallowed_given; ++numargs) {
    if (opt->debug & DEBUG_CONF) {
      log_dbg("Macallowed #%d: %s\n", numargs, 
	      args_info.macallowed_arg[numargs]);
    }
    char *p1 = NULL;
    char *p2 = NULL;
    char *p3 = malloc(strlen(args_info.macallowed_arg[numargs])+1);
    int i;

    unsigned int mac[6];

    strcpy(p3, args_info.macallowed_arg[numargs]);
    p1 = p3;
    if ((p2 = strchr(p1, ','))) {
      *p2 = '\0';
    }
    while (p1) {
      if (opt->macoklen>=MACOK_MAX) {
	log_err(0,"Too many addresses in macallowed %s!",
		args_info.macallowed_arg);
      }
      else {
	/* Replace anything but hex and comma with space */
	for (i=0; i<strlen(p1); i++) 
	  if (!isxdigit(p1[i])) p1[i] = 0x20;
      
	if (sscanf (p1, "%2x %2x %2x %2x %2x %2x",
		    &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
	  log_err(0, "Failed to convert macallowed option to MAC Address");
	}
	else {

	  if (opt->debug & DEBUG_CONF) {
	    log_dbg("Macallowed address #%d: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
		   opt->macoklen,
		   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	  }

	  for (i = 0; i < 6; i++)
	    opt->macok[opt->macoklen][i] = (unsigned char) mac[i]; 

	  opt->macoklen++;
	}
      }
      
      if (p2) {
	p1 = p2+1;
	if ((p2 = strchr(p1, ','))) {
	  *p2 = '\0';
	}
      }
      else {
	p1 = NULL;
      }
    }
    free(p3);
  }

  /** string parameters **/
  if (opt->routeif) free(opt->routeif);
  opt->routeif = STRDUP(args_info.routeif_arg);

  if (opt->wwwdir) free(opt->wwwdir);
  opt->wwwdir = STRDUP(args_info.wwwdir_arg);

  if (opt->wwwbin) free(opt->wwwbin);
  opt->wwwbin = STRDUP(args_info.wwwbin_arg);

  if (opt->uamui) free(opt->uamui);
  opt->uamui = STRDUP(args_info.uamui_arg);

  if (opt->localusers) free(opt->localusers);
  opt->localusers = STRDUP(args_info.localusers_arg);

#ifdef HAVE_OPENSSL
  if (opt->sslkeyfile) free(opt->sslkeyfile);
  opt->sslkeyfile = STRDUP(args_info.sslkeyfile_arg);

  if (opt->sslcertfile) free(opt->sslcertfile);
  opt->sslcertfile = STRDUP(args_info.sslcertfile_arg);
#endif

  if (opt->uamurl) free(opt->uamurl);
  opt->uamurl = STRDUP(args_info.uamserver_arg);

  if (opt->uamhomepage) free(opt->uamhomepage);
  opt->uamhomepage = STRDUP(args_info.uamhomepage_arg);

  if (opt->wisprlogin) free(opt->wisprlogin);
  opt->wisprlogin = STRDUP(args_info.wisprlogin_arg);

  if (opt->uamsecret) free(opt->uamsecret);
  opt->uamsecret = STRDUP(args_info.uamsecret_arg);

  if (opt->proxysecret) free(opt->proxysecret);
  if (!args_info.proxysecret_arg) {
    opt->proxysecret = STRDUP(args_info.radiussecret_arg);
  }
  else {
    opt->proxysecret = STRDUP(args_info.proxysecret_arg);
  }

  if (opt->macsuffix) free(opt->macsuffix);
  opt->macsuffix = STRDUP(args_info.macsuffix_arg);

  if (opt->macpasswd) free(opt->macpasswd);
  opt->macpasswd = STRDUP(args_info.macpasswd_arg);

  if (opt->adminuser) free(opt->adminuser);
  opt->adminuser = STRDUP(args_info.adminuser_arg);

  if (opt->adminpasswd) free(opt->adminpasswd);
  opt->adminpasswd = STRDUP(args_info.adminpasswd_arg);

  if (opt->adminupdatefile) free(opt->adminupdatefile);
  opt->adminupdatefile = STRDUP(args_info.adminupdatefile_arg);

  if (opt->rtmonfile) free(opt->rtmonfile);
  opt->rtmonfile = STRDUP(args_info.rtmonfile_arg);

  if (opt->ssid) free(opt->ssid);
  opt->ssid = STRDUP(args_info.ssid_arg);

  if (opt->vlan) free(opt->vlan);
  opt->vlan = STRDUP(args_info.vlan_arg);

  if (opt->nasmac) free(opt->nasmac);
  opt->nasmac = STRDUP(args_info.nasmac_arg);

  if (opt->nasip) free(opt->nasip);
  opt->nasip = STRDUP(args_info.nasip_arg);

  if (opt->tundev) free(opt->tundev);
  opt->tundev = STRDUP(args_info.tundev_arg);

  if (opt->radiusnasid) free(opt->radiusnasid);
  opt->radiusnasid = STRDUP(args_info.radiusnasid_arg);

  if (opt->radiuslocationid) free(opt->radiuslocationid);
  opt->radiuslocationid = STRDUP(args_info.radiuslocationid_arg);

  if (opt->radiuslocationname) free(opt->radiuslocationname);
  opt->radiuslocationname = STRDUP(args_info.radiuslocationname_arg);

  if (opt->locationname) free(opt->locationname);
  opt->locationname = STRDUP(args_info.locationname_arg);

  if (opt->radiussecret) free(opt->radiussecret);
  opt->radiussecret = STRDUP(args_info.radiussecret_arg);

  if (opt->cmdsocket) free(opt->cmdsocket);
  opt->cmdsocket = STRDUP(args_info.cmdsocket_arg);

  if (opt->domain) free(opt->domain);
  opt->domain = STRDUP(args_info.domain_arg);

  if (opt->ipup) free(opt->ipup);
  opt->ipup = STRDUP(args_info.ipup_arg);

  if (opt->ipdown) free(opt->ipdown);
  opt->ipdown = STRDUP(args_info.ipdown_arg);

  if (opt->conup) free(opt->conup);
  opt->conup = STRDUP(args_info.conup_arg);

  if (opt->condown) free(opt->condown);
  opt->condown = STRDUP(args_info.condown_arg);

  if (opt->pidfile) free(opt->pidfile);
  opt->pidfile = STRDUP(args_info.pidfile_arg);

  if (opt->statedir) free(opt->statedir);
  opt->statedir = STRDUP(args_info.statedir_arg);

  if (opt->usestatusfile) free(opt->usestatusfile);
  opt->usestatusfile = STRDUP(args_info.usestatusfile_arg);

  ret = 0;

  if (args_info.bin_arg) { /* save out the configuration */
    bstring bt = bfromcstr("");
    int ok = options_save(args_info.bin_arg, bt);
    if (!ok) log_err(0, "could not save configuration options!");
    bdestroy(bt);
  }

  if (args_info.reload_flag) {
    if (execl(SBINDIR "/chilli_query", "chilli_query", 
	      args_info.cmdsocket_arg, "reload", (char *) 0) != 0) {
      log_err(errno, "execl() did not return 0!");
      exit(2);
    }
  }

 end_processing:
  cmdline_parser_free (&args_info);

  return ret;
}
