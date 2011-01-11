/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007-2011 Coova Technologies, LLC. <support@coova.com>
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

#include "chilli.h"

#if(0)
static int chilliauth_cb(struct radius_t *radius,
			 struct radius_packet_t *pack,
			 struct radius_packet_t *pack_req, void *cbp) {
  struct radius_attr_t *attr = NULL;
  /*char attrs[RADIUS_ATTR_VLEN+1];*/
  size_t offset = 0;
  
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

int static test_radius() {
  struct radius_t *radius;
  struct radius_packet_t radius_pack;
  struct timeval idleTime;
  int starttime;
  int maxfd = 0;
  fd_set fds;
  int status;

  if (!_options.adminuser || !_options.adminpasswd) return 1;

  if (radius_new(&radius, &_options.radiuslisten, 0, 0, NULL, 0, NULL, NULL, NULL)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "Failed to create radius");
    return -1;
  }

  radius_set(radius, 0, (_options.debug & DEBUG_RADIUS));

  radius_set_cb_auth_conf(radius, chilliauth_cb); 

  {int cnt=0; for (; cnt < RADIUS_QUEUESIZE * 2; cnt++) {

  if (radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REQUEST)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0, "radius_default_pack() failed");
    return -1;
  }
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
		 (uint8_t *)_options.adminuser, strlen(_options.adminuser));

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
		 (uint8_t *)_options.adminpasswd, strlen(_options.adminpasswd));

  radius_addnasip(radius, &radius_pack);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_SERVICE_TYPE, 0, 0,
		 RADIUS_SERVICE_TYPE_ADMIN_USER, NULL, 0); 
  
  if (_options.radiusnasid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
		   (uint8_t *)_options.radiusnasid, strlen(_options.radiusnasid));
  
  if (_options.nasmac)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
		   (uint8_t *)_options.nasmac, strlen(_options.nasmac)); 

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		 _options.radiusnasporttype, NULL, 0);

  if (_options.radiuslocationid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_ID, 0,
		   (uint8_t *)_options.radiuslocationid, strlen(_options.radiuslocationid));

  if (_options.radiuslocationname)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_NAME, 0,
		   (uint8_t *)_options.radiuslocationname, 
		   strlen(_options.radiuslocationname));
  
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

   }};

  radius_free(radius);
  return 0;
}
#endif

struct options_t _options;

int main(int argc, char **argv)
{
  /*  if (process_options(argc, argv, 1))
      exit(1);*/

  {
    char *radsecret = "";
    char *uamsecret = "";
    char *plain = "hello";
    char enc[128];
    char out[128];
    char authenticator[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    size_t enclen;
    size_t outlen;

    printf("plain = %s\n", plain);

    radius_pwencode(0, enc, sizeof(enc), &enclen,
		    plain, strlen(plain), 
		    authenticator, 
		    radsecret, strlen(radsecret));

    printf("enclen = %d\n", enclen);

    radius_pwdecode(0, out, sizeof(out), &outlen,
		    enc, enclen,
		    authenticator, 
		    radsecret, strlen(radsecret));

    printf("out = (%d)%s\n", outlen, out);
  }
  
  /*  return test_radius(); /* */
}
