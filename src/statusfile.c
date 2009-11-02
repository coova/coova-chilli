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
#include "tun.h"
#include "ippool.h"
#include "radius.h"
#include "redir.h"
#include "syserr.h"
#include "dhcp.h"
#include "cmdline.h"
#include "chilli.h"
#include "options.h"
#include "cmdsock.h"

extern time_t mainclock;
extern struct ippool_t *ippool;

#define MARK_START 0x00
#define MARK_NEXT  0x34 /* arbitrary */

#ifdef ENABLE_BINSTATFILE
int loadstatus() {
  char *statedir = _options.statedir ? _options.statedir : DEFSTATEDIR;
  struct stat statbuf;
  char filedest[512];
  char header[512], c;
  FILE *file;

  struct dhcp_conn_t dhcpconn;
  struct app_conn_t appconn;

  if (!_options.usestatusfile) 
    return 1;

  if (strlen(statedir)>sizeof(filedest)-1) 
    return -1;

  if (stat(statedir, &statbuf)) { 
    log_err(errno, "statedir (%s) does not exist", statedir); 
    return -1; 
  }

  if (!S_ISDIR(statbuf.st_mode)) { 
    log_err(0, "statedir (%s) not a directory", statedir); 
    return -1; 
  }

  snprintf(filedest, sizeof(filedest), "%s/%s", statedir, _options.usestatusfile);

  file = fopen(filedest, "r");
  if (!file) { log_err(errno, "could not open file %s", filedest); return -1; }

  while ((c = fgetc(file)) != MARK_START) {
    if (c == EOF) { fclose(file); return -1; }
  }

  while (fread(&dhcpconn, sizeof(struct dhcp_conn_t), 1, file) == 1) {
    struct dhcp_conn_t *conn=0;
    struct ippoolm_t *newipm;
    int n;

    log_info("Loaded dhcp connection %.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	     dhcpconn.hismac[0], dhcpconn.hismac[1],
	     dhcpconn.hismac[2], dhcpconn.hismac[3],
	     dhcpconn.hismac[4], dhcpconn.hismac[5]);

    /* todo: read a md5 checksum or magic token */

    if ((c = fgetc(file)) != MARK_NEXT) {
      fclose(file); 
      return -1;
    }

    dhcp_lnkconn(dhcp, &conn);

    /* set/copy all the pointers */
    dhcpconn.nexthash = conn->nexthash;
    dhcpconn.next = conn->next;
    dhcpconn.prev = conn->prev;
    dhcpconn.parent = dhcp;

    /* initialize dhcp_conn_t */
    memcpy(conn, &dhcpconn, sizeof(struct dhcp_conn_t));

    for (n=0; n < DHCP_DNAT_MAX; n++) {
      memset(conn->dnatmac[n], 0, PKT_ETH_ALEN); 
    }

    /* add into ippool */
    if (ippool_newip(ippool, &newipm, &dhcpconn.hisip, 1)) {
      if (ippool_newip(ippool, &newipm, &dhcpconn.hisip, 0)) {
	log_err(0, "Failed to allocate either static or dynamic IP address");
	fclose(file); 
	return -1;
      }
    }

    dhcp_hashadd(dhcp, conn);

    if (conn->peer) {
      conn->peer = 0;

      if (fread(&appconn, sizeof(struct app_conn_t), 1, file) == 1) {
	struct app_conn_t *aconn = 0;

	if ((c = fgetc(file)) != MARK_NEXT) {
	  fclose(file); 
	  return -1;
	}

	if (newconn(&aconn) == 0) {
	  /* set/copy all the pointers/internals */
	  appconn.unit = aconn->unit;
	  appconn.next = aconn->next;
	  appconn.prev = aconn->prev;
	  appconn.uplink = newipm;
	  appconn.dnlink = conn;

	  /* initialize app_conn_t */
	  memcpy(aconn, &appconn, sizeof(struct app_conn_t));
	  conn->peer = aconn;
	  newipm->peer = aconn;

	  if (appconn.natip.s_addr)
	    assign_snat(aconn, 1);

	  dhcp_set_addrs(conn, 
			 &newipm->addr, &_options.mask, 
			 &aconn->ourip, &aconn->mask,
			 &_options.dns1, &_options.dns2, 
			 _options.domain);
	}

	/* todo: read a md5 checksum or magic token */
      }
      else {
	log_err(errno, "Problem loading state file %s",filedest);
	break;
      }
    }
  } 

  fclose(file);
  printstatus();
  return 0;
}

int printstatus() {
  char *statedir = _options.statedir ? _options.statedir : DEFSTATEDIR;
  char filedest[512];
  struct stat statbuf;
  FILE *file;

  struct dhcp_conn_t *dhcpconn = dhcp->firstusedconn;
  struct app_conn_t *appconn;

  if (!_options.usestatusfile) 
    return 0;

  if (strlen(statedir)>sizeof(filedest)-1) 
    return -1;

  if (stat(statedir, &statbuf)) { 
    log_err(errno, "statedir (%s) does not exist", statedir); 
    return -1; 
  }

  if (!S_ISDIR(statbuf.st_mode)) { 
    log_err(0, "statedir (%s) not a directory", statedir); 
    return -1; 
  }

  snprintf(filedest, sizeof(filedest), "%s/%s", statedir, _options.usestatusfile);

  log_dbg("Writing status file: %s", filedest);

  file = fopen(filedest, "w");
  if (!file) { log_err(errno, "could not open file %s", filedest); return -1; }
  fprintf(file, "#CoovaChilli-Version: %s\n", VERSION);
  fprintf(file, "#Timestamp: %d\n", (int) mainclock);

  /* marker */
  fputc(MARK_START, file);

  while (dhcpconn) {
    fwrite(dhcpconn, sizeof(struct dhcp_conn_t), 1, file);
    fputc(MARK_NEXT, file);
    appconn = (struct app_conn_t *)dhcpconn->peer;
    if (appconn) {
      fwrite(appconn, sizeof(struct app_conn_t), 1, file);
      fputc(MARK_NEXT, file);
    }
    dhcpconn = dhcpconn->next;
  }

  fclose(file);
  return 0;
}
#else
#ifdef ENABLE_STATFILE
int loadstatus() {
  printstatus();
  return 0;
}

int printstatus() {
  char *statedir = _options.statedir ? _options.statedir : DEFSTATEDIR;
  FILE *file;
  char filedest[512];
  struct stat statbuf;

  struct dhcp_conn_t *dhcpconn = dhcp->firstusedconn;
  struct app_conn_t *appconn;

  if (!_options.usestatusfile) 
    return 0;

  if (strlen(statedir)>sizeof(filedest)-1) 
    return -1;

  if (stat(statedir, &statbuf)) { 
    log_err(errno, "statedir (%s) does not exist", statedir); 
    return -1; 
  }

  if (!S_ISDIR(statbuf.st_mode)) { 
    log_err(0, "statedir (%s) not a directory", statedir); 
    return -1; 
  }

  snprintf(filedest, sizeof(filedest), "%s/%s", statedir, _options.usestatusfile);

  file = fopen(filedest, "w");
  if (!file) { log_err(errno, "could not open file %s", filedest); return -1; }
  fprintf(file, "#Version:1.1\n");
  fprintf(file, "#SessionID = SID\n#Start-Time = ST\n");
  fprintf(file, "#SessionTimeOut = STO\n#SessionTerminateTime = STT\n");
  fprintf(file, "#Timestamp: %d\n", (int) mainclock);
  fprintf(file, "#User, IP, MAC, SID, ST, STO, STT\n");

  while(dhcpconn)
  {
    appconn = (struct app_conn_t *)dhcpconn->peer;
    if (appconn && appconn->s_state.authenticated == 1)
    {
      fprintf(file, "%s, %s, %.2X-%.2X-%.2X-%.2X-%.2X-%.2X, %s, %d, %d, %d\n",
	appconn->s_state.redir.username,
	inet_ntoa(appconn->hisip),
	appconn->hismac[0], appconn->hismac[1],
	appconn->hismac[2], appconn->hismac[3],
	appconn->hismac[4], appconn->hismac[5],
	appconn->s_state.sessionid,
	appconn->s_state.start_time,
	appconn->s_params.sessiontimeout,
	appconn->s_params.sessionterminatetime);
    }
    dhcpconn = dhcpconn->next;
  }

  fclose(file);
  return 0;
}
#endif
#endif
