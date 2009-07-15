/* 
 * chilli - A Wireless LAN Access Point Controller
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#ifndef _SESSION_H
#define _SESSION_H

#include "limits.h"
#include "garden.h"

#define SESSION_PASS_THROUGH_MAX 8

struct session_params {
  uint8_t url[REDIR_USERURLSIZE];
  uint8_t filteridbuf[256];
  uint8_t filteridlen;
  uint8_t routeidx;
  uint64_t bandwidthmaxup;
  uint64_t bandwidthmaxdown;
  uint64_t maxinputoctets;
  uint64_t maxoutputoctets;
  uint64_t maxtotaloctets;
  uint64_t sessiontimeout;
  uint32_t idletimeout;
  uint16_t interim_interval;     /* Seconds. 0 = No interim accounting */
  time_t sessionterminatetime;

#define REQUIRE_UAM_AUTH   (1<<0)
#define REQUIRE_UAM_SPLASH (1<<1)
#define REQUIRE_REDIRECT   (1<<2)
#define IS_UAM_REAUTH      (1<<3)
  uint8_t flags;

  pass_through pass_throughs[SESSION_PASS_THROUGH_MAX];
  uint32_t pass_through_count;
} __attribute__((packed));


struct redir_state {

  char username[REDIR_USERNAMESIZE];
  char userurl[REDIR_USERURLSIZE];

  uint8_t uamchal[REDIR_MD5LEN];

  uint8_t classbuf[RADIUS_ATTR_VLEN];
  size_t classlen;

  uint8_t statebuf[RADIUS_ATTR_VLEN];
  unsigned char statelen;

} __attribute__((packed));

struct session_state {
  struct redir_state redir;

  int authenticated;           /* 1 if user was authenticated */  

  char sessionid[REDIR_SESSIONID_LEN]; /* Accounting session ID */

  time_t start_time;
  time_t interim_time;

  time_t last_time; /* Last time a packet was received or sent */
  time_t uamtime;

  uint64_t input_packets;
  uint64_t output_packets;
  uint64_t input_octets;
  uint64_t output_octets;
  uint32_t terminate_cause;
  uint32_t session_id;
  uint16_t tag8021q;

#ifdef LEAKY_BUCKET
  /* Leaky bucket */
  uint64_t bucketup;
  uint64_t bucketdown;
  uint64_t bucketupsize;
  uint64_t bucketdownsize;
#endif

} __attribute__((packed));


int session_json_fmt(struct session_state *state, 
		     struct session_params *params,
		     bstring json, int init);

int session_redir_json_fmt(bstring json, char *userurl, char *redirurl, 
			   bstring logouturl, uint8_t *hismac);

#endif
