/*
 * Chilli sessions
 * Copyright (C) 2004, 2005 Mondru AB.
 * Copyright (c) 2006-2007 David Bird <david@cova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */
#include "system.h"
#include "session.h"

extern time_t mainclock;

int session_redir_json_fmt(bstring json, char *userurl, char *redirurl, uint8_t *hismac) {
  bcatcstr(json,",\"redir\":{\"originalURL\":\"");
  bcatcstr(json, userurl?userurl:"");
  bcatcstr(json,"\",\"redirectionURL\":\"");
  bcatcstr(json, redirurl?redirurl:"");
  bcatcstr(json,"\",\"macAddress\":\"");
  if (hismac) {
    char mac[REDIR_MACSTRLEN+2];
    snprintf(mac, REDIR_MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	     hismac[0], hismac[1],
	     hismac[2], hismac[3],
	     hismac[4], hismac[5]);
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
  time_t timenow = mainclock;
  uint32_t sessiontime;
  uint32_t idletime;
  
  sessiontime = timenow - state->start_time;
  idletime    = timenow - state->last_time;

  bcatcstr(json,",\"session\":{\"sessionId\":\"");
  bcatcstr(json,state->sessionid);
  bcatcstr(json,"\",\"userName\":\"");
  bcatcstr(json,state->redir.username);
  bcatcstr(json, "\",\"startTime\":");
  bassignformat(tmp, "%ld", init ? mainclock : starttime);
  bconcat(json, tmp);
  bcatcstr(json,",\"sessionTimeout\":");
  bassignformat(tmp, "%ld", params->sessiontimeout);
  bconcat(json, tmp);
  bcatcstr(json,",\"idleTimeout\":");
  bassignformat(tmp, "%ld", params->idletimeout);
  bconcat(json, tmp);
  if (params->maxinputoctets) {
    bcatcstr(json,",\"maxInputOctets\":");
    bassignformat(tmp, "%ld", params->maxinputoctets);
    bconcat(json, tmp);
  }
  if (params->maxoutputoctets) {
    bcatcstr(json,",\"maxOutputOctets\":");
    bassignformat(tmp, "%ld", params->maxoutputoctets);
    bconcat(json, tmp);
  }
  if (params->maxtotaloctets) {
    bcatcstr(json,",\"maxTotalOctets\":");
    bassignformat(tmp, "%ld", params->maxtotaloctets);
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

