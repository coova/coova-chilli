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
#include "md5.h"

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

/*
 * Plans (todo):
 *  - "Chilli Dog" will provide a simple RADIUS->HTTP AAA proxy (loosly based on WiFiDog). 
 *  - It should also be able to proxy to an alternate RADIUS server(s). 
 *  - It should also be able to establish and use a RadSec Tunnel. 
 *
 */

typedef struct _proxy_request {

  int index;

  char reserved:6;
  char authorized:1;
  char inuse:1;

  bstring url;

  bstring data;

  bstring post;

  struct radius_packet_t radius_req;
  struct radius_packet_t radius_res;

  struct _proxy_request *prev, *next;
  
} proxy_request;

static int max_requests = 0;
static proxy_request * requests = 0;
static proxy_request * requests_free = 0;

static proxy_request * get_request() {
  proxy_request * req = 0;
  int i;

  if (!max_requests) {

    max_requests = 255;  /* hard maximum! (should be configurable) */

    requests = (proxy_request *) calloc(max_requests, sizeof(proxy_request));
    for (i=0; i < max_requests; i++) {
      requests[i].index = i;
      if (i > 0) 
	requests[i].prev = &requests[i-1];
      if ((i+1) < max_requests) 
	requests[i].next = &requests[i+1];
    }

    requests_free = requests;
  }

  if (requests_free) {
    req = requests_free;
    requests_free = requests_free->next;
    if (requests_free)
      requests_free->prev = 0;
  }

  if (!req) {
    /* problem */
    log_err(0,"out of connections\n");
    return 0;
  }

  req->next = req->prev = 0;
  req->inuse = 1;
  return req;
}

static void close_request(proxy_request *req) {
  req->inuse = 0;
  if (requests_free) {
    requests_free->prev = req;
    req->next = requests_free;
  }
  requests_free = req;
}

static int bstring_data(void *ptr, size_t size, size_t nmemb, void *userdata) {
  bstring s = (bstring) userdata;
  int rsize = size * nmemb;
  bcatblk(s,ptr,rsize);
  return rsize;
}

static int http_aaa(struct radius_t *radius, proxy_request *req) {
  int result = -2;
  CURL *curl;
  CURLcode res;

  char *user = 0;
  char *pwd = 0;
  char *ca = 0;
  char *cert = 0;
  char *key = 0;
  char *keypwd = 0;

  if ((curl = curl_easy_init()) != NULL) {
    struct curl_httppost *formpost=NULL;
    struct curl_httppost *lastptr=NULL;
    char error_buffer[CURL_ERROR_SIZE + 1];

    memset(&error_buffer, 0, sizeof(error_buffer));

    if (req->post) {
      curl_formadd(&formpost,
		   &lastptr,
		   CURLFORM_COPYNAME, "xml",
		   CURLFORM_COPYCONTENTS, req->post->data,
		   CURLFORM_END);

      curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    }

    if (user && pwd) {
    }

    if (cert && strlen(cert)) {
      log_dbg("using cert [%s]",cert);
      curl_easy_setopt(curl, CURLOPT_SSLCERT, cert);
      curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
    }

    if (key && strlen(key)) {
      log_dbg("using key [%s]",key);
      curl_easy_setopt(curl, CURLOPT_SSLKEY, key);
      curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
      if (keypwd && strlen(keypwd)) {
	log_dbg("using key pwd [%s]",keypwd);
#ifdef CURLOPT_SSLCERTPASSWD
	curl_easy_setopt(curl, CURLOPT_SSLCERTPASSWD, keypwd);
#else
#ifdef CURLOPT_SSLKEYPASSWD
	curl_easy_setopt(curl, CURLOPT_SSLKEYPASSWD, keypwd);
#else
#ifdef CURLOPT_KEYPASSWD
	curl_easy_setopt(curl, CURLOPT_KEYPASSWD, keypwd);
#endif
#endif
#endif
      }
    }

    if (ca && strlen(ca)) {
#ifdef CURLOPT_ISSUERCERT
      log_dbg("using ca [%s]",ca);
      curl_easy_setopt(curl, CURLOPT_ISSUERCERT, ca);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
#else
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
#endif
    }
    else {
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    }

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, /*debug ? 1 :*/ 0);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_SSLv3);

    curl_easy_setopt(curl, CURLOPT_URL, req->url->data);
    
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "CoovaChilli");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1); 
    curl_easy_setopt(curl, CURLOPT_NETRC, 0);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, bstring_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, req->data);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, &error_buffer);
    
    if ((res = curl_easy_perform(curl)) != 0) {
      log_err(errno, "curl: failed for url %s [%s] %s", 
	      req->url->data, curl_easy_strerror(res), error_buffer);
      result = -1;
    } else {
      log_dbg("curl: got %s", req->url->data);
      result = 0;
    }
    
    curl_easy_cleanup(curl);
  }

  if (req->data->slen) {
    /*printf("Received: %s\n",req->data->data);/**/
    req->authorized = !memcmp(req->data->data, "Auth: 1", 7);
    log_dbg("Access-%s", req->authorized ? "Accept" : "Reject");
  }

  /* initialize response packet */
  switch(req->radius_req.code) {
  case RADIUS_CODE_ACCOUNTING_REQUEST:
    radius_default_pack(radius, &req->radius_res, RADIUS_CODE_ACCOUNTING_RESPONSE);
    break;
    
  case RADIUS_CODE_ACCESS_REQUEST:
    if (req->authorized) {
      radius_default_pack(radius, &req->radius_res, RADIUS_CODE_ACCESS_ACCEPT);
      break;
    }

  default:
    radius_default_pack(radius, &req->radius_res, RADIUS_CODE_ACCESS_REJECT);
    break;
  }

  req->radius_res.id = req->radius_req.id;

  /* process attributes */
  if (req->data->slen) {
    char *parse = req->data->data;
    if (parse) {
      char *s, *ptr;
      while ((ptr = strtok(parse,"\n"))) {
	parse = 0;

	if (req->authorized) {

	  /* access-accept only */

	  struct {
	    char *n;
	    int a;
	  } attrs[] = {
	    { "Session-Timeout:", RADIUS_ATTR_SESSION_TIMEOUT },
	    { "ChilliSpot-Bandwidth-Max-Up:", RADIUS_ATTR_CHILLISPOT_BANDWIDTH_MAX_UP },
	    { "ChilliSpot-Bandwidth-Max-Down:", RADIUS_ATTR_CHILLISPOT_BANDWIDTH_MAX_DOWN },
	    { "ChilliSpot-Max-Input-Octets:", RADIUS_ATTR_CHILLISPOT_MAX_INPUT_OCTETS },
	    { "ChilliSpot-Max-Output-Octets:", RADIUS_ATTR_CHILLISPOT_MAX_OUTPUT_OCTETS },
	    { "ChilliSpot-Max-Total-Octets:", RADIUS_ATTR_CHILLISPOT_MAX_TOTAL_OCTETS },
	    { "ChilliSpot-Max-Input-Gigawords:", RADIUS_ATTR_CHILLISPOT_MAX_INPUT_GIGAWORDS },
	    { "ChilliSpot-Max-Output-Gigawords:", RADIUS_ATTR_CHILLISPOT_MAX_OUTPUT_GIGAWORDS },
	    { "ChilliSpot-Max-Total-Gigawords:", RADIUS_ATTR_CHILLISPOT_MAX_TOTAL_GIGAWORDS },
	    { 0 }
	  };
	  
	  int i = 0;
	  for (;;i++) {
	    if (!attrs[i].n) break;
	    if (!strncmp(ptr,attrs[i].n,strlen(attrs[i].n))) {
	      int v = atoi(ptr+strlen(attrs[i].n));
	      if (v > 0) {
		radius_addattr(radius, &req->radius_res, attrs[i].a, 0, 0, v, NULL, 0);
		log_dbg("Setting %s = %d\n", attrs[i].n, v);
	      }
	    }
	  }
	}
	/* all packets */
      }
    }
  }

  /* finish off RADIUS respose */
  switch(req->radius_req.code) {
    
  case RADIUS_CODE_ACCESS_REQUEST:
    {
      struct radius_attr_t *ma = NULL;
      
      radius_addattr(radius, &req->radius_res, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		     0, 0, 0, NULL, RADIUS_MD5LEN);
      
      memset(req->radius_res.authenticator, 0, RADIUS_AUTHLEN);
      memcpy(req->radius_res.authenticator, req->radius_req.authenticator, RADIUS_AUTHLEN);
      
      if (!radius_getattr(&req->radius_res, &ma, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 0,0,0)) {
	radius_hmac_md5(radius, &req->radius_res, radius->secret, radius->secretlen, ma->v.t);
      }
      
      radius_authresp_authenticator(radius, &req->radius_res, 
				    req->radius_req.authenticator,
				    radius->secret,
				    radius->secretlen);
    }
    break;
    
  case RADIUS_CODE_ACCOUNTING_REQUEST:
    radius_acctreq_authenticator(radius, &req->radius_res);
    break;
  }

  return result;
}

static int radius_reply(struct radius_t *this,
			struct radius_packet_t *pack,
			struct sockaddr_in *peer) {

  size_t len = ntohs(pack->length);
  
  if (sendto(this->fd, pack, len, 0,(struct sockaddr *) peer, 
	     sizeof(struct sockaddr_in)) < 0) {
    log_err(errno, "sendto() failed!");
    return -1;
  } 
  
  return 0;
}

static void process_radius(struct radius_t *radius, struct radius_packet_t *pack, struct sockaddr_in *peer) {
  struct radius_attr_t *attr = NULL; 
  char *error = 0;

  proxy_request *req = get_request();

  bstring tmp;
  bstring tmp2;

  if (!req) return;

  tmp = bfromcstralloc(10,"");
  tmp2 = bfromcstralloc(10,"");

  if (!req->url) req->url = bfromcstr("");
  if (!req->data) req->data = bfromcstr("");

  memcpy(&req->radius_req, pack, sizeof(struct radius_packet_t));
  memset(&req->radius_res, '0', sizeof(struct radius_packet_t));

  bassigncstr(req->data, "");

  bassignformat(req->url, "%s%s", "http://localhost/simple-dog.php", "?");

  switch(req->radius_req.code) {
  case RADIUS_CODE_ACCESS_REQUEST:
    bcatcstr(req->url, "stage=login");
    break;
  case RADIUS_CODE_ACCOUNTING_REQUEST:
    bcatcstr(req->url, "stage=counters");
    break;
  default:
    error = "Unsupported RADIUS code";
    break;
  }

  if (!error) {
    if (radius_getattr(pack, &attr, RADIUS_ATTR_SERVICE_TYPE, 0,0,0)) {
      error = "No service-type in RADIUS packet";
    } else {
      bcatcstr(req->url, "&service=");
      switch (ntohl(attr->v.i)) {
      case RADIUS_SERVICE_TYPE_LOGIN:
	bcatcstr(req->url, "login");
	break;
      case RADIUS_SERVICE_TYPE_FRAMED:
	bcatcstr(req->url, "framed");
	break;
      default:
	bassignformat(tmp, "%d", ntohl(attr->v.i));
	bconcat(req->url, tmp);
	break;
      }
    }
  }
  
  if (!error) {
    if (radius_getattr(pack, &attr, RADIUS_ATTR_USER_NAME, 0,0,0)) {
      error = "No user-name in RADIUS packet";
    } else {
      bcatcstr(req->url, "&user=");
      bassignblk(tmp, attr->v.t, attr->l-2);
      redir_urlencode(tmp, tmp2);
      bconcat(req->url, tmp2);
    }
  }

  if (!error) {
    if (radius_getattr(pack, &attr, RADIUS_ATTR_CALLED_STATION_ID, 0,0,0)) {
      error = "No called-station-id in RADIUS packet";
    }
    bcatcstr(req->url, "&ap=");
    bassignblk(tmp, attr->v.t, attr->l-2);
    redir_urlencode(tmp, tmp2);
    bconcat(req->url, tmp2);
  }
  
  if (!error) {
    if (radius_getattr(pack, &attr, RADIUS_ATTR_CALLING_STATION_ID, 0,0,0)) {
      error = "No calling-station-id in RADIUS packet";
    }
    bcatcstr(req->url, "&mac=");
    bassignblk(tmp, attr->v.t, attr->l-2);
    redir_urlencode(tmp, tmp2);
    bconcat(req->url, tmp2);
  }

  if (!error) {
    if (!radius_getattr(pack, &attr, RADIUS_ATTR_ACCT_SESSION_ID, 0,0,0)) {
      bcatcstr(req->url, "&sessionid=");
      bassignblk(tmp, attr->v.t, attr->l-2);
      redir_urlencode(tmp, tmp2);
      bconcat(req->url, tmp2);
    }
    if (!radius_getattr(pack, &attr, RADIUS_ATTR_NAS_IDENTIFIER, 0,0,0)) {
      bcatcstr(req->url, "&nasid=");
      bassignblk(tmp, attr->v.t, attr->l-2);
      redir_urlencode(tmp, tmp2);
      bconcat(req->url, tmp2);
    }
  }

  if (!error) {
    MD5_CTX context;
    unsigned char cksum[16];
    char hex[32+1];
    int i;

    MD5Init(&context);
    MD5Update(&context, (uint8_t*)req->url->data, req->url->slen);
    MD5Update(&context, (uint8_t*)radius->secret, strlen(radius->secret));
    MD5Final(cksum, &context);

    hex[0]=0;
    for (i=0; i<16; i++)
      sprintf(hex+strlen(hex), "%.2X", cksum[i]);

    bcatcstr(req->url, "&md=");
    bcatcstr(req->url, hex);
  }
  
  log_dbg("==> %s", req->url->data);

  http_aaa(radius, req);

  radius_reply(radius, &req->radius_res, peer);

  close_request(req);
}

int main(int argc, char **argv) {
  struct gengetopt_args_info args_info;
  struct options_t * opt;
  struct radius_packet_t radius_pack;
  struct radius_t *radius_auth;
  struct radius_t *radius_acct;
  struct in_addr radiuslisten;
  int maxfd = 0;
  fd_set fds;
  int status;

  bstring optbt = bfromcstr("");

  options_set(opt = (struct options_t *)calloc(1, sizeof(struct options_t)));
  process_options(argc, argv, 1);

  curl_global_init(CURL_GLOBAL_ALL);
  
  radiuslisten.s_addr = htonl(INADDR_ANY);

  if (radius_new(&radius_auth, &radiuslisten, 11812, 0, NULL, 0, NULL, NULL, NULL)) {
    log_err(0, "Failed to create radius");
    return -1;
  }

  if (radius_new(&radius_acct, &radiuslisten, 11813, 0, NULL, 0, NULL, NULL, NULL)) {
    log_err(0, "Failed to create radius");
    return -1;
  }

  radius_set(radius_auth, 0, 0);
  radius_set(radius_acct, 0, 0);

  while (1) {
    FD_ZERO(&fds);
    FD_SET(radius_auth->fd, &fds);
    FD_SET(radius_acct->fd, &fds);

    maxfd = radius_auth->fd > radius_acct->fd ? radius_auth->fd : radius_acct->fd;
    
    switch (status = select(maxfd + 1, &fds, NULL, NULL, NULL)) {
    case -1:
      log_err(errno, "select() returned -1!");
      break;  
    case 0:
    default:
      break;
    }
    
    if (status > 0) {
      struct sockaddr_in addr;
      socklen_t fromlen = sizeof(addr);

      if (FD_ISSET(radius_auth->fd, &fds)) {
	/*
	 *    ---> Authentication
	 */

	if ((status = recvfrom(radius_auth->fd, &radius_pack, sizeof(radius_pack), 0, 
			       (struct sockaddr *) &addr, &fromlen)) <= 0) {
	  log_err(errno, "recvfrom() failed");

	  return -1;
	}

	process_radius(radius_auth, &radius_pack, &addr);
      }

      if (FD_ISSET(radius_acct->fd, &fds)) {
	/*
	 *    ---> Accounting
	 */

	if ((status = recvfrom(radius_acct->fd, &radius_pack, sizeof(radius_pack), 0, 
			       (struct sockaddr *) &addr, &fromlen)) <= 0) {
	  log_err(errno, "recvfrom() failed");
	  return -1;
	}

	process_radius(radius_acct, &radius_pack, &addr);
      }
    }
  }

  curl_global_cleanup();
}
