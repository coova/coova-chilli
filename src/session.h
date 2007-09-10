/* 
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

#define SESSION_PASS_THROUGH_MAX 4

struct session_params {
  uint8_t url[REDIR_USERURLSIZE];
  uint8_t filteridbuf[256];
  uint8_t filteridlen;
  uint32_t bandwidthmaxup;
  uint32_t bandwidthmaxdown;
  uint64_t maxinputoctets;
  uint64_t maxoutputoctets;
  uint64_t maxtotaloctets;
  uint64_t sessiontimeout;
  uint32_t idletimeout;
  uint16_t interim_interval;     /* Seconds. 0 = No interim accounting */
  time_t sessionterminatetime;
  char require_uam_auth;
  char require_redirect;

  pass_through pass_throughs[SESSION_PASS_THROUGH_MAX];
  uint32_t pass_through_count;
} __attribute__((packed));


#endif
