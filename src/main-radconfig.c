/* 
 *
 * chilli - ChilliSpot.org. A Wireless LAN Access Point Controller.
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2006 PicoPoint B.V.
 * Copyright (c) 2006 Coova Ltd
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
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

static int chilliauth_cb(struct radius_t *radius,
			 struct radius_packet_t *pack,
			 struct radius_packet_t *pack_req, void *cbp) {
  struct radius_attr_t *attr = NULL;
  char attrs[RADIUS_ATTR_VLEN+1];
  int offset = 0;

  if (!pack) { 
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Radius request timed out");
    return 0;
  }

  if ((pack->code != RADIUS_CODE_ACCESS_REJECT) && 
      (pack->code != RADIUS_CODE_ACCESS_CHALLENGE) &&
      (pack->code != RADIUS_CODE_ACCESS_ACCEPT)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, 
	    "Unknown radius access reply code %d", pack->code);
    return 0;
  }

  /* ACCESS-ACCEPT */
  if (pack->code != RADIUS_CODE_ACCESS_ACCEPT) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Administrative-User Login Failed");
    return 0;
  }

  while (!radius_getnextattr(pack, &attr, 
			     RADIUS_ATTR_VENDOR_SPECIFIC,
			     RADIUS_VENDOR_CHILLISPOT,
			     RADIUS_ATTR_CHILLISPOT_CONFIG, 
			     0, &offset)) {
    char value[RADIUS_ATTR_VLEN+1] = "";
    strncpy(value, (const char *)attr->v.t, attr->l - 2);
    printf("%s\n", value);
  }

  return 0;
  
}

int static chilliauth_radius() {
  struct radius_t *radius;
  struct radius_packet_t radius_pack;
  struct timeval idleTime;
  int starttime;
  int maxfd = 0;
  fd_set fds;
  int status;

  if (!options.adminuser || !options.adminpasswd) return 1;

  if (radius_new(&radius, &options.radiuslisten, 0, 0, NULL, 0, NULL, NULL, NULL)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Failed to create radius");
    return -1;
  }

  radius_set(radius, (options.debug & DEBUG_RADIUS),
	     &options.radiusserver1, &options.radiusserver2,
	     options.radiusauthport, options.radiusacctport,
	     options.radiussecret);

  radius_set_cb_auth_conf(radius, chilliauth_cb); 

  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REQUEST)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "radius_default_pack() failed");
    return -1;
  }
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
		 (uint8_t *)options.adminuser, strlen(options.adminuser));

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
		 (uint8_t *)options.adminpasswd, strlen(options.adminpasswd));

  radius_addnasip(radius, &radius_pack);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_SERVICE_TYPE, 0, 0,
		 RADIUS_SERVICE_TYPE_ADMIN_USER, NULL, 0); 
  
  if (options.radiusnasid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
		   (uint8_t *)options.radiusnasid, strlen(options.radiusnasid));
  
  if (options.nasmac)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
		   (uint8_t *)options.nasmac, strlen(options.nasmac)); 

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		 options.radiusnasporttype, NULL, 0);

  if (options.radiuslocationid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_ID, 0,
		   (uint8_t *)options.radiuslocationid, strlen(options.radiuslocationid));

  if (options.radiuslocationname)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_NAME, 0,
		   (uint8_t *)options.radiuslocationname, 
		   strlen(options.radiuslocationname));
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		 0, 0, 0, NULL, RADIUS_MD5LEN);

  radius_req(radius, &radius_pack, NULL); 

  if (radius->fd <= 0) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "not a valid socket!");
    return -1;
  } 

  maxfd = radius->fd;

  starttime = time(NULL);
  while ((starttime + REDIR_RADIUS_MAX_TIME) > time(NULL)) {
    FD_ZERO(&fds);
    FD_SET(radius->fd, &fds);
    
    idleTime.tv_sec = 0;
    idleTime.tv_usec = REDIR_RADIUS_SELECT_TIME;
    radius_timeleft(radius, &idleTime);

    switch (status = select(maxfd + 1, &fds, NULL, NULL, &idleTime)) {
    case -1:
      sys_err(LOG_ERR, __FILE__, __LINE__, errno, "select() returned -1!");
      break;  
    case 0:
      radius_timeout(radius);
    default:
      break;
    }

    if (status > 0) {
      if (FD_ISSET(radius->fd, &fds)) {
	if (radius_decaps(radius) < 0) {
	  sys_err(LOG_ERR, __FILE__, __LINE__, 0, "radius_ind() failed!");
	}
	break;
      }
    }
  }  

  radius_free(radius);
  return 0;
}

int main(int argc, char **argv)
{
  if (process_options(argc, argv, 1))
    exit(1);
  
  return chilliauth_radius();
}
