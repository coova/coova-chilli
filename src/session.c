/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
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
#include "session.h"
#include "dhcp.h"
#include "radius.h"
#include "chilli.h"

#ifdef ENABLE_JSON
int session_redir_json_fmt(bstring json, char *userurl, char *redirurl, 
			   bstring logouturl, uint8_t *hismac) {
  bcatcstr(json,",\"redir\":{\"originalURL\":\"");
  bcatcstr(json, userurl?userurl:"");
  bcatcstr(json,"\",\"redirectionURL\":\"");
  bcatcstr(json, redirurl?redirurl:"");
  if (logouturl) {
    bcatcstr(json,"\",\"logoutURL\":\"");
    bconcat(json, logouturl);
  }
  bcatcstr(json,"\",\"macAddress\":\"");
  if (hismac) {
    char mac[REDIR_MACSTRLEN+2];
    snprintf(mac, REDIR_MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	     (unsigned int)hismac[0], (unsigned int)hismac[1],
	     (unsigned int)hismac[2], (unsigned int)hismac[3],
	     (unsigned int)hismac[4], (unsigned int)hismac[5]);
    bcatcstr(json, mac);
  }
  bcatcstr(json,"\"}");
  return 0;
}

int session_json_fmt(struct session_state *state, 
		     struct session_params *params,
		     bstring json, int init) {
  bstring tmp = bfromcstr("");
  time_t starttime = state->start_time;
  uint32_t inoctets = state->input_octets;
  uint32_t outoctets = state->output_octets;
  uint32_t ingigawords = (state->input_octets >> 32);
  uint32_t outgigawords = (state->output_octets >> 32);
  uint32_t sessiontime;
  uint32_t idletime;
  
  sessiontime = mainclock_diffu(state->start_time);
  idletime    = mainclock_diffu(state->last_sent_time);

  bcatcstr(json,",\"session\":{\"sessionId\":\"");
  bcatcstr(json,state->sessionid);
  bcatcstr(json,"\",\"userName\":\"");
  bcatcstr(json,state->redir.username);
  bcatcstr(json, "\",\"startTime\":");
  bassignformat(tmp, "%ld", init ? mainclock_now() : starttime);
  bconcat(json, tmp);
  bcatcstr(json,",\"sessionTimeout\":");
  bassignformat(tmp, "%lld", params->sessiontimeout);
  bconcat(json, tmp);
  bcatcstr(json,",\"idleTimeout\":");
  bassignformat(tmp, "%ld", params->idletimeout);
  bconcat(json, tmp);
#ifdef ENABLE_IEEE8021Q
  if (state->tag8021q) {
    bcatcstr(json,",\"vlan\":");
    bassignformat(tmp, "%d", (int)(ntohl(state->tag8021q) & 0x0FFF));
    bconcat(json, tmp);
  }
#endif
  if (params->maxinputoctets) {
    bcatcstr(json,",\"maxInputOctets\":");
    bassignformat(tmp, "%lld", params->maxinputoctets);
    bconcat(json, tmp);
  }
  if (params->maxoutputoctets) {
    bcatcstr(json,",\"maxOutputOctets\":");
    bassignformat(tmp, "%lld", params->maxoutputoctets);
    bconcat(json, tmp);
  }
  if (params->maxtotaloctets) {
    bcatcstr(json,",\"maxTotalOctets\":");
    bassignformat(tmp, "%lld", params->maxtotaloctets);
    bconcat(json, tmp);
  }
  bcatcstr(json,"}");

  bcatcstr(json,",\"accounting\":{\"sessionTime\":");
  bassignformat(tmp, "%ld", init ? 0 : sessiontime);
  bconcat(json, tmp);
  bcatcstr(json,",\"idleTime\":");
  bassignformat(tmp, "%ld", init ? 0 : idletime);
  bconcat(json, tmp);
  bcatcstr(json,",\"inputOctets\":");
  bassignformat(tmp, "%ld",init ? 0 :  inoctets);
  bconcat(json, tmp);
  bcatcstr(json,",\"outputOctets\":");
  bassignformat(tmp, "%ld", init ? 0 : outoctets);
  bconcat(json, tmp);
  bcatcstr(json,",\"inputGigawords\":");
  bassignformat(tmp, "%ld", init ? 0 : ingigawords);
  bconcat(json, tmp);
  bcatcstr(json,",\"outputGigawords\":");
  bassignformat(tmp, "%ld", init ? 0 : outgigawords);
  bconcat(json, tmp);
  bcatcstr(json,"}");

  bdestroy(tmp);
  return 0;
}
#endif

