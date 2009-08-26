/* 
 * Copyright (C) 2003-2005 Mondru AB.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */
#ifndef _LIMITS_H
#define _LIMITS_H

/*
 * extracted from various .h files, needs some cleanup.
 */

/* If the constants below are defined packets which have been dropped
   by the traffic shaper will be counted towards accounting and
   volume limitation */
/* #define COUNT_DOWNLINK_DROP 1 */
/* #define COUNT_UPLINK_DROP 1 */

/*#define BUCKET_SIZE                   300000 -* Size of leaky bucket (~200 packets) */
/* Time length of leaky bucket in milliseconds */
/* Bucket size = BUCKET_TIME * Bandwidth-Max radius attribute */
/* Not used if BUCKET_SIZE is defined */
#define BUCKET_TIME                     5000  /* 5 seconds */
#define BUCKET_SIZE_MIN                15000 /* Minimum size of leaky bucket (~10 packets) */
#define CHECK_INTERVAL                     3 /* Time between checking connections */

/* options */
#define OPT_IPADDRLEN                    256
#define OPT_IDLETIME                      10 /* Options idletime between each select */

/* redir */
#define REDIR_MAXLISTEN                   32
#define REDIR_MAXTIME                    100 /* Seconds */
#define REDIR_HTTP_MAX_TIME               10 /* Seconds */
#define REDIR_HTTP_SELECT_TIME        500000 /* microseconds = 0.5 seconds */
#define REDIR_RADIUS_MAX_TIME             60 /* Seconds */
#define REDIR_RADIUS_SELECT_TIME      500000 /* microseconds = 0.5 seconds */
#define REDIR_CHALLEN                     16
#define REDIR_MD5LEN                      16
#define REDIR_MACSTRLEN                   17
#define REDIR_MAXBUFFER                 5125

#define REDIR_USERNAMESIZE               256 /* Max length of username */
#define REDIR_MAXQUERYSTRING            2048
#define REDIR_USERURLSIZE               2048 /* Max length of URL requested by user */
#define REDIR_USERAGENTSIZE              256
#define REDIR_COOKIESIZE                 256
#define REDIR_LANGSIZE                    16
#define REDIR_IDENTSIZE                   16

#define REDIR_MAXCONN                     16

#define REDIR_URL_LEN                   2048
#define REDIR_SESSIONID_LEN               17

/* chilli */
#define EAP_LEN                         2048 /* TODO: Rather large */
#define MACSTRLEN                         17
#define MS2SUCCSIZE                       40 /* MS-CHAPv2 authenticator response as ASCII */
#define DATA_LEN                        1500 /* Max we allow */
#define USERNAMESIZE                     256 /* Max length of username */
#define CHALLENGESIZE                     24 /* From chap.h MAX_CHALLENGE_LENGTH */
#define USERURLSIZE                      256 /* Max length of URL requested by user */

/* dhcp */
#define DHCP_DEBUG                         0 /* Print debug information */
#define DHCP_MTU                        1492 /* Maximum MTU size */

/* radius */
#define RADIUS_SECRETSIZE                128 /* No secrets that long */
#define RADIUS_MD5LEN                     16 /* Length of MD5 hash */
#define RADIUS_AUTHLEN                    16 /* RFC 2865: Length of authenticator */
#define RADIUS_PWSIZE                    128 /* RFC 2865: Max 128 octets in password */
#define RADIUS_CHAPSIZE                   24 
#define RADIUS_QUEUESIZE                 256 /* Same size as id address space */
#define RADIUS_ATTR_VLEN                 253
#define RADIUS_PACKSIZE                 4096
#define RADIUS_HDRSIZE                    20
#define RADIUS_MPPEKEYSSIZE               32 /* Length of MS_CHAP_MPPE_KEYS attribute */ 

#define UAMSERVER_MAX                      8

#ifdef ENABLE_LARGELIMITS
#define SESSION_PASS_THROUGH_MAX          16
#define MAX_PASS_THROUGHS                512 /* Max number of allowed UAM pass-throughs */
#define MAX_UAM_DOMAINS                   56 /* Max number of allowed UAM domains */
#define MACOK_MAX                         56
#else
#define SESSION_PASS_THROUGH_MAX           8
#define MAX_PASS_THROUGHS                128 /* Max number of allowed UAM pass-throughs */
#define MAX_UAM_DOMAINS                   32 /* Max number of allowed UAM domains */
#define MACOK_MAX                         16
#endif

#endif
