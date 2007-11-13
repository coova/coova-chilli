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

struct options_t options;

char *STRDUP(char *s) {
  if (!s) return 0;
  while (isspace(*s)) s++;
  if (!*s) return 0;
  return strdup(s);
}

/* Get IP address and mask */
int option_aton(struct in_addr *addr, struct in_addr *mask,
		char *pool, int number) {

  /* Parse only first instance of network for now */
  /* Eventually "number" will indicate the token which we want to parse */

  unsigned int a1, a2, a3, a4;
  unsigned int m1, m2, m3, m4;
  unsigned int m;
  int masklog;
  int c;

  c = sscanf(pool, "%u.%u.%u.%u/%u.%u.%u.%u",
	     &a1, &a2, &a3, &a4,
	     &m1, &m2, &m3, &m4);

  switch (c) {
  case 4:
    mask->s_addr = 0xffffffff;
    break;
  case 5:
    if (m1 > 32) {
      log_err(0, "Invalid mask");
      return -1; /* Invalid mask */
    }
    mask->s_addr = htonl(0xffffffff << (32 - m1));
    break;
  case 8:
    if (m1 >= 256 ||  m2 >= 256 || m3 >= 256 || m4 >= 256) {
      log_err(0, "Invalid mask");
      return -1; /* Wrong mask format */
    }
    m = m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4;
    for (masklog = 0; ((1 << masklog) < ((~m)+1)); masklog++);
    if (((~m)+1) != (1 << masklog)) {
      log_err(0, "Invalid mask");
      return -1; /* Wrong mask format (not all ones followed by all zeros)*/
    }
    mask->s_addr = htonl(m);
    break;
  default:
    log_err(0, "Invalid mask");
    return -1; /* Invalid mask */
  }

  if (a1 >= 256 ||  a2 >= 256 || a3 >= 256 || a4 >= 256) {
    log_err(0, "Wrong IP address format");
    return -1;
  }
  else
    addr->s_addr = htonl(a1 * 0x1000000 + a2 * 0x10000 + a3 * 0x100 + a4);

  return 0;
}

static const char *description = 
  "CoovaChilli - A Wireless LAN Access Point Controller.\n"
  "  For more information on this project, visit: \n"
  "  http://coova.org/wiki/index.php/CoovaChilli\n";

static const char *copyright = 
  "Copyright (c) 2003-2005 Mondru AB., 2006-2007 David Bird, and others.\n"
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


/* Extract domain name and port from URL */
int static get_namepart(char *src, char *host, int hostsize, int *port) {
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

int process_options(int argc, char **argv, int minimal) {
  int reconfiguring = options.initialized;
  struct gengetopt_args_info args_info;
  struct hostent *host;
  char hostname[USERURLSIZE];
  int numargs;
  int ret = -1;

  if (!reconfiguring)
    memset(&options, 0, sizeof(options));

  memset(&args_info, 0, sizeof(args_info));

  if (cmdline_parser(argc, argv, &args_info) != 0) {
    log_err(0, "Failed to parse command line options");
    goto end_processing;
  }

  if (args_info.version_given) {
    options_print_version();
    exit(0);
  }

  if (args_info.help_given) {
    options_print_help();
    exit(0);
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
  if (!reconfiguring && res_init()) {
    log_err(0, "Failed to update system DNS settings (res_init()!");
    goto end_processing;
  }

  /* Handle each option */
  options.initialized = 1;

  if (args_info.debug_flag) 
    options.debug = args_info.debugfacility_arg;
  else 
    options.debug = 0;

  /** simple configuration parameters **/
  options.usetap = args_info.usetap_flag;
  options.foreground = args_info.fg_flag;
  options.interval = args_info.interval_arg;
  options.lease = args_info.lease_arg;
  options.dhcpstart = args_info.dhcpstart_arg;
  options.dhcpend = args_info.dhcpend_arg;
  options.eapolenable = args_info.eapolenable_flag;
  options.swapoctets = args_info.swapoctets_flag;
  options.usestatusfile = args_info.usestatusfile_flag;
  options.logfacility = args_info.logfacility_arg;
  options.chillixml = args_info.chillixml_flag;
  options.macauth = args_info.macauth_flag;
  options.uamport = args_info.uamport_arg;
  options.uamuiport = args_info.uamuiport_arg;
  options.macallowlocal = args_info.macallowlocal_flag;
  options.no_uamsuccess = args_info.nouamsuccess_flag;
  options.no_uamwispr = args_info.nouamwispr_flag;
  options.wpaguests = args_info.wpaguests_flag;
  options.openidauth = args_info.openidauth_flag;
  options.defsessiontimeout = args_info.defsessiontimeout_arg;
  options.definteriminterval = args_info.definteriminterval_arg;
  options.defidletimeout = args_info.defidletimeout_arg;
  options.radiusnasporttype = args_info.radiusnasporttype_arg;
  options.radiusauthport = args_info.radiusauthport_arg;
  options.radiusacctport = args_info.radiusacctport_arg;
  options.coaport = args_info.coaport_arg;
  options.coanoipcheck = args_info.coanoipcheck_flag;
  options.radiustimeout = args_info.radiustimeout_arg;
  options.radiusretry = args_info.radiusretry_arg;
  options.radiusretrysec = args_info.radiusretrysec_arg;
  options.proxyport = args_info.proxyport_arg;
  options.txqlen = args_info.txqlen_arg;
  options.postauth_proxyport = args_info.postauthproxyport_arg;
  options.pap_always_ok = args_info.papalwaysok_flag;
  options.acct_update = args_info.acctupdate_flag;

  if (!reconfiguring) {
    options.dhcpif = STRDUP(args_info.dhcpif_arg);
  }

  if (!args_info.radiussecret_arg) {
    log_err(0, "radiussecret must be specified!");
    goto end_processing;
  }

  if (!args_info.dhcpmac_arg) {
    memset(options.dhcpmac, 0, PKT_ETH_ALEN);
    options.dhcpusemac  = 0;
  }
  else {
    unsigned int temp[PKT_ETH_ALEN];
    char macstr[RADIUS_ATTR_VLEN];
    int macstrlen;
    int	i;

    if ((macstrlen = strlen(args_info.dhcpmac_arg)) >= (RADIUS_ATTR_VLEN-1)) {
      log_err(0,
	      "MAC address too long");
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
    
    for(i = 0; i < PKT_ETH_ALEN; i++) 
      options.dhcpmac[i] = temp[i];

    options.dhcpusemac  = 1;
  }

  if (!reconfiguring) {
    if (args_info.net_arg) {
      if (option_aton(&options.net, &options.mask, args_info.net_arg, 0)) {
	log_err(0, "Invalid network address: %s!", args_info.net_arg);
	goto end_processing;
      }
      if (!args_info.uamlisten_arg) {
	options.uamlisten.s_addr = htonl(ntohl(options.net.s_addr)+1);
      }
      else if (!inet_aton(args_info.uamlisten_arg, &options.uamlisten)) {
	log_err(0, "Invalid UAM IP address: %s!", args_info.uamlisten_arg);
	goto end_processing;
      }
      options.dhcplisten.s_addr = options.uamlisten.s_addr;
    }
    else if (!minimal) {
      log_err(0, "Network address must be specified ('net' parameter)!");
      goto end_processing;
    }
  }

  log_dbg("DHCP Listen: %s", inet_ntoa(options.dhcplisten));
  log_dbg("UAM Listen: %s", inet_ntoa(options.uamlisten));

  if (!args_info.uamserver_arg && !minimal) {
    log_err(0, "WARNING: No uamserver defiend!");
  }

  if (args_info.uamserver_arg) {
    if (options.debug & DEBUG_CONF) {
      log_dbg("Uamserver: %s\n", args_info.uamserver_arg);
    }
    memset(options.uamserver, 0, sizeof(options.uamserver));
    options.uamserverlen = 0;
    if (get_namepart(args_info.uamserver_arg, hostname, USERURLSIZE, 
		     &options.uamserverport)) {
      log_err(0, "Failed to parse uamserver: %s!", args_info.uamserver_arg);
      goto end_processing;
    }
  
    if (!(host = gethostbyname(hostname))) {
      log_err(0, 
	      "Could not resolve IP address of uamserver: %s! [%s]", 
	      args_info.uamserver_arg, strerror(errno));
      goto end_processing;
    }
    else {
      int j = 0;
      while (host->h_addr_list[j] != NULL) {
	if (options.debug & DEBUG_CONF) {
	  log_dbg("Uamserver IP address #%d: %s\n", j,
		 inet_ntoa(*(struct in_addr*) host->h_addr_list[j]));
	}
	if (options.uamserverlen>=UAMSERVER_MAX) {
	  log_err(0,
		  "Too many IPs in uamserver %s!",
		  args_info.uamserver_arg);
	  goto end_processing;
	}
	else {
	  options.uamserver[options.uamserverlen++] = 
	    *((struct in_addr*) host->h_addr_list[j++]);
	}
      }
    }
  }

  if (args_info.uamhomepage_arg) {
    if (get_namepart(args_info.uamhomepage_arg, hostname, USERURLSIZE, 
		     &options.uamhomepageport)) {
      log_err(0,
	      "Failed to parse uamhomepage: %s!", args_info.uamhomepage_arg);
      goto end_processing;
    }

    if (!(host = gethostbyname(hostname))) {
      log_err(0, 
	      "Invalid uamhomepage: %s! [%s]", 
	      args_info.uamhomepage_arg, strerror(errno));
      goto end_processing;
    }
    else {
      int j = 0;
      while (host->h_addr_list[j] != NULL) {
	if (options.uamserverlen>=UAMSERVER_MAX) {
	  log_err(0,
		  "Too many IPs in uamhomepage %s!",
		  args_info.uamhomepage_arg);
	  goto end_processing;
	}
	else {
	  options.uamserver[options.uamserverlen++] = 
	    *((struct in_addr*) host->h_addr_list[j++]);
	}
      }
    }
  }

  options.uamanydns = args_info.uamanydns_flag;
  options.uamanyip = args_info.uamanyip_flag;
  options.dnsparanoia = args_info.dnsparanoia_flag;
  options.radiusoriginalurl = args_info.radiusoriginalurl_flag;

  /* pass-throughs */
  memset(options.pass_throughs, 0, sizeof(options.pass_throughs));
  options.num_pass_throughs = 0;

  for (numargs = 0; numargs < args_info.uamallowed_given; ++numargs) {
    pass_throughs_from_string(options.pass_throughs,
			      MAX_PASS_THROUGHS,
			      &options.num_pass_throughs,
			      args_info.uamallowed_arg[numargs]);
  }

  if (options.uamdomains) {
    for (numargs = 0; options.uamdomains[numargs]; ++numargs) 
      free(options.uamdomains[numargs]);
    free(options.uamdomains);
  }
  options.uamdomains=0;

  if (args_info.uamdomain_given) {
    options.uamdomains = calloc(args_info.uamdomain_given+1, sizeof(char *));
    for (numargs = 0; numargs < args_info.uamdomain_given; ++numargs) 
      options.uamdomains[numargs] = STRDUP(args_info.uamdomain_arg[numargs]);
  }

  if (!reconfiguring) {
    options.allowdyn = 1;
    if (!args_info.dynip_arg) {
      options.dynip = STRDUP(args_info.net_arg);
    }
    else {
      struct in_addr addr;
      struct in_addr mask;
      options.dynip = STRDUP(args_info.dynip_arg);
      if (option_aton(&addr, &mask, options.dynip, 0)) {
	log_err(0,
		"Failed to parse dynamic IP address pool!");
	goto end_processing;
      }
    }
    
    /* statip                                                        */
    if (args_info.statip_arg) {
      struct in_addr addr;
      struct in_addr mask;
      options.statip = STRDUP(args_info.statip_arg);
      if (option_aton(&addr, &mask, options.statip, 0)) {
	log_err(0,
		"Failed to parse static IP address pool!");
	return -1;
      }
      options.allowstat = 1;
    }
    else {
      options.allowstat = 0;
    }
  }

  if (args_info.dns1_arg) {
    if (!inet_aton(args_info.dns1_arg, &options.dns1)) {
      log_err(0,
	      "Invalid primary DNS address: %s!", 
	      args_info.dns1_arg);
      goto end_processing;
    }
  }
  else if (_res.nscount >= 1) {
    options.dns1 = _res.nsaddr_list[0].sin_addr;
  }
  else {
    options.dns1.s_addr = 0;
  }

  if (args_info.dns2_arg) {
    if (!inet_aton(args_info.dns2_arg, &options.dns2)) {
      log_err(0,
	      "Invalid secondary DNS address: %s!", 
	      args_info.dns1_arg);
      goto end_processing;
    }
  }
  else if (_res.nscount >= 2) {
    options.dns2 = _res.nsaddr_list[1].sin_addr;
  }
  else {
    options.dns2.s_addr = options.dns1.s_addr;
  }


  /* If no listen option is specified listen to any local port    */
  /* Do hostname lookup to translate hostname to IP address       */
  if (!reconfiguring) {
    if (args_info.radiuslisten_arg) {
      if (!(host = gethostbyname(args_info.radiuslisten_arg))) {
	log_err(0, "Invalid listening address: %s! [%s]", 
		args_info.radiuslisten_arg, strerror(errno));
	goto end_processing;
      }
      else {
	memcpy(&options.radiuslisten.s_addr, host->h_addr, host->h_length);
      }
    }
    else {
      options.radiuslisten.s_addr = htonl(INADDR_ANY);
    }
  }

  if (args_info.uamlogoutip_arg) {
    if (!(host = gethostbyname(args_info.uamlogoutip_arg))) {
      log_warn(0, "Invalid uamlogoutup address: %s! [%s]", 
	       args_info.uamlogoutip_arg, strerror(errno));
    }
    else {
      memcpy(&options.uamlogout.s_addr, host->h_addr, host->h_length);
    }
  }

  if (args_info.postauthproxy_arg) {
    if (!(host = gethostbyname(args_info.postauthproxy_arg))) {
      log_warn(0, "Invalid postauthproxy address: %s! [%s]", 
	       args_info.postauthproxy_arg, strerror(errno));
    }
    else {
      memcpy(&options.postauth_proxyip.s_addr, host->h_addr, host->h_length);
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
      memcpy(&options.radiusserver1.s_addr, host->h_addr, host->h_length);
    }
  }
  else {
    log_err(0,
	    "No radiusserver1 address given!");
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
      memcpy(&options.radiusserver2.s_addr, host->h_addr, host->h_length);
    }
  }
  else {
    options.radiusserver2.s_addr = 0;
  }

  /* If no listen option is specified listen to any local port    */
  /* Do hostname lookup to translate hostname to IP address       */
  if (!reconfiguring) {
    if (args_info.proxylisten_arg) {
      if (!(host = gethostbyname(args_info.proxylisten_arg))) {
	log_err(0, 
		"Invalid listening address: %s! [%s]", 
		args_info.proxylisten_arg, strerror(errno));
	goto end_processing;
      }
      else {
	memcpy(&options.proxylisten.s_addr, host->h_addr, host->h_length);
      }
    }
    else {
      options.proxylisten.s_addr = htonl(INADDR_ANY);
    }

    /* Store proxyclient as in_addr net and mask                       */
    if (args_info.proxyclient_arg) {
      if(option_aton(&options.proxyaddr, &options.proxymask, 
		     args_info.proxyclient_arg, 0)) {
	log_err(0,
		"Invalid proxy client address: %s!", args_info.proxyclient_arg);
	goto end_processing;
      }
    }
    else {
      options.proxyaddr.s_addr = ~0; /* Let nobody through */
      options.proxymask.s_addr = 0; 
    }
  }


  memset(options.macok, 0, sizeof(options.macok));
  options.macoklen = 0;
  for (numargs = 0; numargs < args_info.macallowed_given; ++numargs) {
    if (options.debug & DEBUG_CONF) {
      log_dbg("Macallowed #%d: %s\n", numargs, 
	      args_info.macallowed_arg[numargs]);
    }
    char *p1 = NULL;
    char *p2 = NULL;
    char *p3 = malloc(strlen(args_info.macallowed_arg[numargs])+1);
    int i;
    strcpy(p3, args_info.macallowed_arg[numargs]);
    p1 = p3;
    if ((p2 = strchr(p1, ','))) {
      *p2 = '\0';
    }
    while (p1) {
      if (options.macoklen>=MACOK_MAX) {
	log_err(0,
		"Too many addresses in macallowed %s!",
		args_info.macallowed_arg);
      }
      else {
	/* Replace anything but hex and comma with space */
	for (i=0; i<strlen(p1); i++) 
	  if (!isxdigit(p1[i])) p1[i] = 0x20;
      
	if (sscanf (p1, "%2x %2x %2x %2x %2x %2x",
		    &options.macok[options.macoklen][0], 
		    &options.macok[options.macoklen][1], 
		    &options.macok[options.macoklen][2], 
		    &options.macok[options.macoklen][3], 
		    &options.macok[options.macoklen][4], 
		    &options.macok[options.macoklen][5]) != 6) {
	  log_err(0, "Failed to convert macallowed option to MAC Address");
	}
	else {
	  if (options.debug & DEBUG_CONF) {
	    log_dbg("Macallowed address #%d: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
		   options.macoklen,
		   options.macok[options.macoklen][0],
		   options.macok[options.macoklen][1],
		   options.macok[options.macoklen][2],
		   options.macok[options.macoklen][3],
		   options.macok[options.macoklen][4],
		   options.macok[options.macoklen][5]);
	  }
	  options.macoklen++;
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
  if (options.wwwdir) free(options.wwwdir);
  options.wwwdir = STRDUP(args_info.wwwdir_arg);

  if (options.wwwbin) free(options.wwwbin);
  options.wwwbin = STRDUP(args_info.wwwbin_arg);

  if (options.uamui) free(options.uamui);
  options.uamui = STRDUP(args_info.uamui_arg);

  if (options.localusers) free(options.localusers);
  options.localusers = STRDUP(args_info.localusers_arg);

  if (options.uamurl) free(options.uamurl);
  options.uamurl = STRDUP(args_info.uamserver_arg);

  if (options.uamhomepage) free(options.uamhomepage);
  options.uamhomepage = STRDUP(args_info.uamhomepage_arg);

  if (options.wisprlogin) free(options.wisprlogin);
  options.wisprlogin = STRDUP(args_info.wisprlogin_arg);

  if (options.uamsecret) free(options.uamsecret);
  options.uamsecret = STRDUP(args_info.uamsecret_arg);

  if (options.proxysecret) free(options.proxysecret);
  if (!args_info.proxysecret_arg) {
    options.proxysecret = STRDUP(args_info.radiussecret_arg);
  }
  else {
    options.proxysecret = STRDUP(args_info.proxysecret_arg);
  }

  if (options.macsuffix) free(options.macsuffix);
  options.macsuffix = STRDUP(args_info.macsuffix_arg);

  if (options.macpasswd) free(options.macpasswd);
  options.macpasswd = STRDUP(args_info.macpasswd_arg);

  if (options.adminuser) free(options.adminuser);
  options.adminuser = STRDUP(args_info.adminuser_arg);

  if (options.adminpasswd) free(options.adminpasswd);
  options.adminpasswd = STRDUP(args_info.adminpasswd_arg);

  if (options.ssid) free(options.ssid);
  options.ssid = STRDUP(args_info.ssid_arg);

  if (options.nasmac) free(options.nasmac);
  options.nasmac = STRDUP(args_info.nasmac_arg);

  if (options.nasip) free(options.nasip);
  options.nasip = STRDUP(args_info.nasip_arg);

  if (options.tundev) free(options.tundev);
  options.tundev = STRDUP(args_info.tundev_arg);

  if (options.radiusnasid) free(options.radiusnasid);
  options.radiusnasid = STRDUP(args_info.radiusnasid_arg);

  if (options.radiuslocationid) free(options.radiuslocationid);
  options.radiuslocationid = STRDUP(args_info.radiuslocationid_arg);

  if (options.radiuslocationname) free(options.radiuslocationname);
  options.radiuslocationname = STRDUP(args_info.radiuslocationname_arg);

  if (options.locationname) free(options.locationname);
  options.locationname = STRDUP(args_info.locationname_arg);

  if (options.radiussecret) free(options.radiussecret);
  options.radiussecret = STRDUP(args_info.radiussecret_arg);

  if (options.cmdsocket) free(options.cmdsocket);
  options.cmdsocket = STRDUP(args_info.cmdsocket_arg);

  if (options.domain) free(options.domain);
  options.domain = STRDUP(args_info.domain_arg);

  if (options.ipup) free(options.ipup);
  options.ipup = STRDUP(args_info.ipup_arg);

  if (options.ipdown) free(options.ipdown);
  options.ipdown = STRDUP(args_info.ipdown_arg);

  if (options.conup) free(options.conup);
  options.conup = STRDUP(args_info.conup_arg);

  if (options.condown) free(options.condown);
  options.condown = STRDUP(args_info.condown_arg);

  if (options.pidfile) free(options.pidfile);
  options.pidfile = STRDUP(args_info.pidfile_arg);

  if (options.statedir) free(options.statedir);
  options.statedir = STRDUP(args_info.statedir_arg);

  ret = 0;

 end_processing:
  cmdline_parser_free (&args_info);

  return ret;
}

void reprocess_options(int argc, char **argv) {
  struct options_t options2;
  log_err(0, "Rereading configuration file and doing DNS lookup");

  memcpy(&options2, &options, sizeof(options)); /* Save original */
  if (process_options(argc, argv, 0)) {
    log_err(0, "Error reading configuration file!");
    memcpy(&options, &options2, sizeof(options));
  }
}

