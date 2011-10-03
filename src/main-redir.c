/* 
 * Copyright (C) 2011 Coova Technologies, LLC. <support@coova.com>
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

#define MAIN_FILE

#include "chilli.h"
#include "debug.h"

struct options_t _options;

static select_ctx sctx;

#ifndef USING_IPC_UNIX
#error This requires the UNIX IPC method
#endif

static int max_requests = 0;
static redir_request * requests = 0;
static redir_request * requests_free = 0;

#ifdef ENABLE_REDIRINJECT
static char *inject_script = "<script src='%s'></script>\r\n";
static char * inject_fmt(char *b, size_t blen, char *url) {
  if (!url || !*url) url = _options.inject;
  safe_snprintf(b, blen, inject_script, url);
  return b;
}
#endif

static bstring string_init_reset(bstring s) {
  if (!s) return bfromcstr("");
  bassigncstr(s, "");
  return s;
}

static redir_request * get_request() {
  redir_request * req = 0;
  int i;
  
  if (!max_requests) {

    max_requests = 2048; /* hard maximum! (should be configurable) */
    
    requests = (redir_request *) calloc(max_requests, sizeof(redir_request));
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
    if (_options.debug) {
      int cnt = 0;
      req = requests_free;
      while (req) {	
	req = req->next;
	cnt++;
      }
      log_dbg("redir free connections %d", cnt);;
    }
    req = requests_free;
    requests_free = requests_free->next;
    if (requests_free)
      requests_free->prev = 0;
  }
  
  if (!req) {
    /* problem */
    log_err(0,"out of connections!");
    return 0;
  }

  req->wbuf = string_init_reset(req->wbuf);
  req->hbuf = string_init_reset(req->hbuf);

  /*
    log_dbg("url->len  %d",req->url->slen);
    log_dbg("data->len %d",req->data->slen);
    log_dbg("post->len %d",req->post->slen);
    log_dbg("wbuf->len %d",req->wbuf->slen);
  */
  
  req->state = 0;
  req->next = req->prev = 0;
  req->html = req->proxy = req->headers = 0;
  req->chunked = req->gzip = 0;
  req->clen = -1;
  req->inuse = 1;
  return req;
}

static void close_request(redir_request *req) {
  log_dbg("closing request");
  req->inuse = 0;
  req->proxy = 0;
  req->socket_fd = 0;
  req->state = 0;
  req->last_active = 0;
  if (requests_free) {
    requests_free->prev = req;
    req->next = requests_free;
  }
  requests_free = req;
}

static int 
sock_redir_getstate(struct redir_t *redir, 
		    struct sockaddr_in *address,
		    struct sockaddr_in *baddress,
		    struct redir_conn_t *conn) {
  struct redir_msg_t msg;
  struct sockaddr_un remote;
  size_t len = sizeof(remote);
  int s;

  char filedest[512];

  statedir_file(filedest, sizeof(filedest), _options.unixipc, "chilli.ipc");

  memset(&msg, 0, sizeof(msg));
  msg.mtype = REDIR_MSG_STATUS_TYPE;
  memcpy(&msg.mdata.address, address, sizeof(msg.mdata.address));
  memcpy(&msg.mdata.baddress, baddress, sizeof(msg.mdata.baddress));

  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return -1;
  }

  memset(&remote, 0, sizeof(remote));

  remote.sun_family = AF_UNIX;
  strcpy(remote.sun_path, filedest);

#if defined (__FreeBSD__)  || defined (__APPLE__) || defined (__OpenBSD__)
  remote.sun_len = strlen(remote.sun_path) + 1;
#endif

  len = offsetof(struct sockaddr_un, sun_path) + strlen(remote.sun_path);

  if (safe_connect(s, (struct sockaddr *)&remote, len) == -1) {
    log_err(errno, "could not connect to %s", remote.sun_path);
    close(s);
    return -1;
  }
  
  if (safe_write(s, &msg, sizeof(msg)) != sizeof(msg)) {
    log_err(errno, "could not write to %s", remote.sun_path);
    close(s);
    return -1;
  }

  if (safe_read(s, conn, sizeof(*conn)) != sizeof(*conn)) {
    log_warn(0, "no session available from %s", remote.sun_path);
    close(s);
    return -1;
  }

  close(s);

  return conn->s_state.authenticated == 1;
}

static int redir_conn_finish(struct conn_t *conn, void *ctx) {
  redir_request *req = (redir_request *)ctx;

  if (req->conn.sock) {
    if (req->state & REDIR_CONN_FD) {
      net_select_rmfd(&sctx, req->conn.sock);
    }
    conn_close(&req->conn);
  }

  if (req->socket_fd) {

#ifdef ENABLE_REDIRINJECT
    if (*req->inject_url && req->html && !req->chunked) {
      char b[256];
      char *inject = inject_fmt(b, sizeof(b), req->inject_url);
      int w = net_write(req->socket_fd, inject, strlen(inject));
      log_dbg("injected %d bytes", w);
    }
#endif
    
    if (req->state & REDIR_SOCKET_FD) {
      net_select_rmfd(&sctx, req->socket_fd);
    }
    close(req->socket_fd);
  }

  close_request(req);
  return 0;
}

static int redir_conn_read(struct conn_t *conn, void *ctx) {
  redir_request *req = (redir_request *)ctx;
  char bb[PKT_MAX_LEN];
  char *b = bb;

  int r = safe_read(conn->sock, b, sizeof(b)-1);

#if(_debug_ > 1)
  log_dbg("conn_read: %d", r);
#endif

  if (r <= 0) {

    redir_conn_finish(conn, ctx);

  } else if (r > 0) {

    b[r]=0;
    req->last_active = mainclock_tick();

#ifdef ENABLE_REDIRINJECT
    /**
     *
     */
    if (*req->inject_url && !req->headers) {
      char *newline = "\r\n\r\n";
      char *eoh;

      bcatblk(req->hbuf, b, r);

      if ((eoh = strstr((char *)req->hbuf->data, newline))) {
	bstring newhdr = bfromcstr("");
	char *hdr, *p;

	hdr = (char *)req->hbuf->data;
	
	while (hdr && *hdr) {
	  int l;
	  int skip = 0;

	  p = strstr(hdr, "\r\n");

	  if (p == hdr) {
	    break;
	  } else if (p) {
	    l = (p - hdr);
	  } else {
	    l = (eoh - hdr);
	  }

	  if (!strncasecmp(hdr, "content-length:", 15)) {
	    char tmp[128];
	    char c = hdr[l];
	    int clen;

	    char b[256];
	    char *inject = inject_fmt(b, sizeof(b), req->inject_url);

	    hdr[l] = 0;
	    clen = req->clen = atoi(hdr+15);
	    log_dbg("Detected Content Length %d", req->clen);
	    clen += strlen(inject);
	    safe_snprintf(tmp, sizeof(tmp), "Content-Length: %d\r\n", clen);
	    bcatcstr(newhdr, tmp);
	    hdr[l] = c;
	    skip = 1;
	  } else if (!strncasecmp(hdr, "accept-ranges:", 14)) {
	    skip = 1;
	  } else if (!strncasecmp(hdr, "content-type:", 13)) {
	    if (strstr(hdr, "text/html")) {
	      req->html = 1;
	    }
	  } else if (strcasestr(hdr, "content-encoding: gzip")) {
	    req->gzip = 1;
	  } else if (strcasestr(hdr, "transfer-encoding: chunked")) {
	    req->chunked = 1;
	  }

	  log_dbg("Header [%d] %.*s%s", l, l, hdr, skip ? " [Skipped]" : "");

	  if (!skip) {
	    bcatblk(newhdr, hdr, l + 2);
	  }

	  hdr += l + 2;
	  if (!p) break;
	}

	/* process headers */
	/* Is HTML */
	/* Check content-encoding chunked */
	/* Adjust content-length */

	net_write(req->socket_fd, newhdr->data, newhdr->slen);
	net_write(req->socket_fd, newline, 2);
	
	if (req->html && req->chunked) {
	  char tmp[56]; int w;

	  char b[256];
	  char *inject = inject_fmt(b, sizeof(b), req->inject_url);
	  
	  safe_snprintf(tmp, sizeof(tmp), "%x\r\n", strlen(inject));
	  net_write(req->socket_fd, tmp, strlen(tmp));
	  w = net_write(req->socket_fd, inject, strlen(inject));
#if(_debug_ > 1)
	  log_dbg("--->>> chunked write %d", w);
#endif
	  net_write(req->socket_fd, "\r\n", 2);
	}
	
	net_write(req->socket_fd, eoh + 4, req->hbuf->slen - 
		  (hdr - (char *)req->hbuf->data) - 2);
	
	req->headers = 1;
	bdestroy(newhdr);
      }
    }
    else {
#endif

      int w = net_write(req->socket_fd, b, r);

#if(_debug_ > 1)      
      log_dbg("write: %d", w);
      /*log_dbg("write: [%s]", b);*/
#endif
      
      if (r != w) {
	log_err(errno, "problem writing what we read");
	redir_conn_finish(conn, ctx);
      }
#ifdef ENABLE_REDIRINJECT
    }
#endif
  }
  return 0;
}

static int
check_regex(regex_t *re, char *regex, char *s) {
  int ret;

#if(_debug_)
  log_dbg("Checking %s =~ %s", s, regex);
#endif

#if defined (__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)
  if (!re->re_g)
#else
  if (!re->allocated) 
#endif
  {
    if ((ret = regcomp(re, regex, REG_EXTENDED | REG_NOSUB)) != 0) {
      char error[512];
      regerror(ret, re, error, sizeof(error));
      log_err(0, "regcomp(%s) failed (%s)", regex, error);
      regex[0] = 0;
      return -1;
    }
  }
  
  if ((ret = regexec(re, s, 0, 0, 0)) == 0) {
    
    log_dbg("Matched regex %s", regex);
    return 0;
    
  }

  return 1;
}

static int 
redir_handle_url(struct redir_t *redir, 
		 struct redir_conn_t *conn, 
		 struct redir_httpreq_t *httpreq,
		 struct redir_socket_t *socket,
		 struct sockaddr_in *peer, 
		 redir_request *req) {
  int port = 80;
  int i;
  int matches = 1;

#ifdef ENABLE_REDIRINJECT
  char hasInject = 0;
  if (conn->s_params.flags & UAM_INJECT_URL) {
    safe_strncpy((char *) req->inject_url,
		 (char *) conn->s_params.url,
		 REDIRINJECT_MAX);
    hasInject = 1;
  } else if  (_options.inject) { 
    safe_strncpy((char *) req->inject_url,
		 (char *) _options.inject,
		 REDIRINJECT_MAX);
    hasInject = 1;
  } else
#endif
    
  for (i=0; i < MAX_REGEX_PASS_THROUGHS; i++) {
    
    if ( ! _options.regex_pass_throughs[i].inuse )
      break;

    /*
    if ( ! _options.regex_pass_throughs[i].regex_host[0] &&
	 ! _options.regex_pass_throughs[i].regex_path[0] &&
	 ! _options.regex_pass_throughs[i].regex_qs[0] )
      break;
    */

#if(_debug_)
    log_dbg("REGEX host=[%s] path=[%s] qs=[%s]",
	    _options.regex_pass_throughs[i].regex_host,
	    _options.regex_pass_throughs[i].regex_path,
	    _options.regex_pass_throughs[i].regex_qs);

    log_dbg("Host %s", httpreq->host);
#endif

    if (_options.regex_pass_throughs[i].regex_host[0]) {
      switch(check_regex(&_options.regex_pass_throughs[i].re_host, 
			 _options.regex_pass_throughs[i].regex_host, 
			 httpreq->host)) {
      case -1: return -1;  
      case 1: matches = _options.regex_pass_throughs[i].neg_host; break;
      case 0: matches = !_options.regex_pass_throughs[i].neg_host; break;
      }
    }

    if (matches && _options.regex_pass_throughs[i].regex_path[0]) {
      switch(check_regex(&_options.regex_pass_throughs[i].re_path, 
			 _options.regex_pass_throughs[i].regex_path, 
			 httpreq->path)) {
      case -1: return -1;  
      case 1: matches = _options.regex_pass_throughs[i].neg_path; break;
      case 0: matches = !_options.regex_pass_throughs[i].neg_path; break;
      }
    }

    if (matches && _options.regex_pass_throughs[i].regex_qs[0]) {
      switch(check_regex(&_options.regex_pass_throughs[i].re_qs, 
			 _options.regex_pass_throughs[i].regex_qs, 
			 httpreq->qs)) {
      case -1: return -1;  
      case 1: matches = _options.regex_pass_throughs[i].neg_qs; break;
      case 0: matches = !_options.regex_pass_throughs[i].neg_qs; break;
      }
    }

    if (matches) break;
  }

  if (matches) {
    log_dbg("Matched for Host %s", httpreq->host);
    
    req->proxy = 1;
    
#ifdef ENABLE_REDIRINJECT
    /* XXX */
    /* Check for headers we wish to filter out */
    if (hasInject) {
      bstring newhdr = bfromcstr("");
      char *hdr = (char *)req->wbuf->data;
      
      while (hdr && *hdr) {
	char *p = strstr(hdr, "\r\n");
	int skip = 0;
	int l;
	
	if (p) {
	  l = (p - hdr);
	} else {
	  l = req->wbuf->slen - (hdr - (char*)req->wbuf->data);
	}
	
	if (!strncasecmp(hdr, "accept-encoding:", 16)) {
	  bcatcstr(newhdr, "Accept-Encoding: identity\r\n");
	  skip = 1;
	} else if (!strncasecmp(hdr, "connection:", 11)) {
	  bcatcstr(newhdr, "Connection: close\r\n");
	  skip = 1;
	} else if (!strncasecmp(hdr, "keep-alive:", 11)) {
	  skip = 1;
	}
	
	if (!skip)
	  bcatblk(newhdr, hdr, l);
	
	if (p) {
	  if (!skip)
	    bcatblk(newhdr, p, 2);
	  hdr = p + 2;
	} else { 
	  hdr = 0;
	}
      }
      
      if (req->wbuf->slen != newhdr->slen) {
	log_dbg("Changed HTTP Headers");
      }
      
      bassign(req->wbuf, newhdr);
      bdestroy(newhdr);
    }
    /* XXX */
#endif
    
    if (conn_setup(&req->conn, httpreq->host, port, req->wbuf, 0)) {
      log_err(errno, "conn_setup()");
      return -1;
    }
    
    req->state |= REDIR_CONN_FD;
    net_select_addfd(&sctx, req->conn.sock, SELECT_READ);
    
    return 0;
  }
  
  return 1;
}

int redir_accept2(struct redir_t *redir, int idx) {
  int status;
  int new_socket;
  struct sockaddr_in address;
  struct sockaddr_in baddress;
  socklen_t addrlen;
  char buffer[128];

  addrlen = sizeof(struct sockaddr_in);

  if ((new_socket = safe_accept(redir->fd[idx], 
				(struct sockaddr *)&address, 
				&addrlen)) < 0) {
    if (errno != ECONNABORTED)
      log_err(errno, "accept()");
    
    return 0;
  }

#if(_debug_)
  log_dbg("new redir socket %d from %s", new_socket, 
	  inet_ntoa(address.sin_addr));
#endif
  
  addrlen = sizeof(struct sockaddr_in);

  if (getsockname(new_socket, (struct sockaddr *)&baddress, 
		  &addrlen) < 0) {
    log_warn(errno, "getsockname() failed!");
  }

  if (ndelay_on(new_socket) < 0) {
    log_err(errno, "could not set ndelay");
  }
  
  if (idx == 1 && _options.uamui) {
    
    if ((status = redir_fork(new_socket, new_socket)) < 0) {
      log_err(errno, "fork() returned -1!");
      close(new_socket);
      return 0;
    }
    
    if (status > 0) { /* Parent */
      close(new_socket);
      return 0; 
    }
    
    safe_snprintf(buffer,sizeof(buffer),"%s",inet_ntoa(address.sin_addr));
    setenv("TCPREMOTEIP",buffer,1);
    setenv("REMOTE_ADDR",buffer,1);
    safe_snprintf(buffer,sizeof(buffer),"%d",ntohs(address.sin_port));
    setenv("TCPREMOTEPORT",buffer,1);
    setenv("REMOTE_PORT",buffer,1);
    
    char *binqqargs[2] = { _options.uamui, 0 } ;
    
    execv(*binqqargs, binqqargs);
    
  } else {

    redir_request *req = get_request();

    log_dbg("redir_main() for %s", inet_ntoa(address.sin_addr));

    req->last_active = mainclock_tick();
    memcpy(&req->conn.peer, &address, sizeof (struct sockaddr_in));
    memcpy(&req->baddr, &baddress, sizeof (struct sockaddr_in));

    req->uiidx = idx;
    req->socket_fd = new_socket;

    conn_set_readhandler(&req->conn, redir_conn_read, req);
    conn_set_donehandler(&req->conn, redir_conn_finish, req);
    
    switch (redir_main(redir, new_socket, new_socket,
		       &address, &baddress, idx, req)) {
    case 1:
      log_dbg("redir queued %s", inet_ntoa(address.sin_addr));
      req->state |= REDIR_SOCKET_FD;
      net_select_addfd(&sctx, req->socket_fd, SELECT_READ);
      return 1;
    case 0: 
      log_dbg("redir completed %s", inet_ntoa(address.sin_addr));
      redir_conn_finish(&req->conn, req);
      return 0;
    default:
      redir_conn_finish(&req->conn, req);
      return -1;
    }
  }

  return 0;
}

int main(int argc, char **argv) {
  int status;
  int idx;
  int active_last = 0;
  int active = 0;

  struct redir_t *redir;

  int keep_going = 1;
  int reload_config = 0;

  uint8_t hwaddr[6];
  struct ifreq ifr;

  int selfpipe;
  
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  options_init();

  chilli_signals(&keep_going, &reload_config);
  
  process_options(argc, argv, 1);
  
  safe_strncpy(ifr.ifr_name, _options.dhcpif, sizeof(ifr.ifr_name));

#ifdef SIOCGIFHWADDR  
  if (ioctl(fd, SIOCGIFHWADDR, (caddr_t)&ifr) == 0) {
    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, PKT_ETH_ALEN);
  } else {
    log_err(errno, "could not get MAC address");
    return -1;
  }
#endif  

  close(fd);
  
  /* create an instance of redir */
  if (redir_new(&redir, &_options.uamlisten, _options.uamport, 
#ifdef ENABLE_UAMUIPORT
		_options.uamuiport
#else
		0
#endif
		)) {
    log_err(0, "Failed to create redir");
    return -1;
  }
  
  if (redir_listen(redir)) {
    log_err(0, "Failed to create redir listen");
    return -1;
  }

  redir_set(redir, hwaddr, (_options.debug));
  redir_set_cb_getstate(redir, sock_redir_getstate);
  
  redir->cb_handle_url = redir_handle_url;

  if (net_select_init(&sctx))
    log_err(errno, "select init");

  selfpipe = selfpipe_init();

  /* epoll */
  net_select_addfd(&sctx, selfpipe, SELECT_READ);
  net_select_addfd(&sctx, redir->fd[0], SELECT_READ);
  net_select_addfd(&sctx, redir->fd[1], SELECT_READ);

  if (_options.gid && setgid(_options.gid)) {
    log_err(errno, "setgid(%d) failed while running with gid = %d\n", 
	    _options.gid, getgid());
  }
  
  if (_options.uid && setuid(_options.uid)) {
    log_err(errno, "setuid(%d) failed while running with uid = %d\n", 
	    _options.uid, getuid());
  }

  while (keep_going) {

    /* select/poll */
    net_select_zero(&sctx);
    net_select_fd(&sctx, selfpipe, SELECT_READ);
    net_select_fd(&sctx, redir->fd[0], SELECT_READ);
    net_select_fd(&sctx, redir->fd[1], SELECT_READ);
  
    active = 0;

    if (reload_config) {
      reload_options(argc, argv);
      reload_config = 0;

      redir_set(redir, hwaddr, _options.debug);
    }

    for (idx=0; idx < max_requests; idx++) {

      conn_select_fd(&requests[idx].conn, &sctx);

      if (requests[idx].inuse && requests[idx].socket_fd) {
	time_t now = mainclock_tick();
	int fd = requests[idx].socket_fd;
	int timeout = 60;

	if (now - requests[idx].last_active > timeout) {
	  log_dbg("timeout connection %d", idx);
	  redir_conn_finish(&requests[idx].conn, &requests[idx]);
	} else {
	  timeout = 0;
	  net_select_fd(&sctx, fd, SELECT_READ);
	  active++;
	}
	
#if(_debug_ > 1)
	if (_options.debug) {
	  struct sockaddr_in address;
	  socklen_t addrlen = sizeof(address);
	  
	  if (getpeername(requests[idx].socket_fd, (struct sockaddr *)&address, 
			  &addrlen) >= 0) {
	    char line[512];
	    
	    safe_snprintf(line, sizeof(line),
			  "#%d (%d) %d connection from %s %d",
			  timeout ? -1 : active, fd, (int) requests[idx].last_active,
			  inet_ntoa(address.sin_addr),
			  ntohs(address.sin_port));
	    
	    if (requests[idx].conn.sock) {
	      addrlen = sizeof(address);
	      if (getpeername(requests[idx].conn.sock, (struct sockaddr *)&address,
			      &addrlen) >= 0) {
		safe_snprintf(line+strlen(line), sizeof(line)-strlen(line),
			      " to %s %d",
			      inet_ntoa(address.sin_addr),
			      ntohs(address.sin_port));
	      }
	    }
	    
	    if (timeout) {
	      safe_snprintf(line+strlen(line), sizeof(line)-strlen(line),
			    " (timeout)");
	    }

	    log_dbg("%s", line);
	  }
	}
#endif
      }
    }

    if (active != active_last) {
      log_dbg("active connections: %d", active);
      active_last = active;
    }
    
    status = net_select(&sctx);
    
#if defined(USING_POLL) && defined(HAVE_SYS_EPOLL_H) && (_debug_ > 1)
    if (_options.debug && status > 0) {
      int i;
      log_dbg("epoll %d", status);
      for (i=0; i < status; i++) {
	log_dbg("epoll fd %d %d", 
		sctx.events[i].data.fd, 
		sctx.events[i].events);
      }
    }
#endif

    switch (status) {
    case -1:
      log_err(errno, "select() returned -1!");
      break;  

    default:
      if (status > 0) {

	if (net_select_read_fd(&sctx, selfpipe))
	  chilli_handle_signal(0, 0);

	if (redir->fd[0])
	  if (net_select_read_fd(&sctx, redir->fd[0]) && 
	      redir_accept2(redir, 0) < 0)
	    log_err(0, "redir_accept() failed!");
	
	if (redir->fd[1])
	  if (net_select_read_fd(&sctx, redir->fd[1]) && 
	      redir_accept2(redir, 1) < 0)
	    log_err(0, "redir_accept() failed!");
      
	for (idx=0; idx < max_requests; idx++) {
	  
	  conn_select_update(&requests[idx].conn, &sctx);
	
	  if (requests[idx].inuse && requests[idx].socket_fd) {
	    int fd = requests[idx].socket_fd;
	    
#ifdef HAVE_SSL
	    if (requests[idx].sslcon) {
	      if (openssl_check_accept(requests[idx].sslcon, 0) < 0) {
		redir_conn_finish(&requests[idx].conn, &requests[idx]);
		continue;
	      }
	    }
#endif
	    
	    switch (net_select_read_fd(&sctx, fd)) {
	    case -1:
	      {
		log_dbg("EXCEPTION");
	      }
	      break;

	    case 1:
	      {
		if (requests[idx].proxy) {
		  char b[1500];
		  int r;
		  
#ifdef HAVE_SSL
		  if (requests[idx].sslcon) {
		    /*
		      log_dbg("proxy_read_ssl");
		    */
		    r = openssl_read(requests[idx].sslcon, 
				     b, sizeof(b)-1, 0);
		  } else
#endif
		    r = recv(fd, b, sizeof(b)-1, 0);
		  
		  /*
		    log_dbg("proxy_read: %d %d", fd, r);
		  */
		  
		  if (r <= 0) {

		    redir_conn_finish(&requests[idx].conn, &requests[idx]);
		    
		  } else if (r > 0) {

		    int w;
		    requests[idx].last_active = mainclock_tick();
		    w = safe_write(requests[idx].conn.sock, b, r);
		    
		    /*
		      log_dbg("proxy_write: %d", w);
		    */
		    if (r != w) {
		      log_err(errno, "problem writing what we read");
		      redir_conn_finish(&requests[idx].conn, &requests[idx]);
		    }
		  }
		  
		} else {
#ifdef HAVE_SSL
		go_again:
#endif
		  switch (redir_main(redir, fd, fd, 
				     &requests[idx].conn.peer,
				     &requests[idx].baddr, 
				     requests[idx].uiidx, 
				     &requests[idx])) {
		  case 1:
		    /*log_dbg("redir cont'ed");*/
#ifdef HAVE_SSL
		    if (requests[idx].sslcon && 
			openssl_pending(requests[idx].sslcon) > 0) {
		      log_dbg("ssl_pending, trying again");
		      goto go_again;
		    }
#endif
		  break;
		  case -1: 
		    log_dbg("redir error");
		  default:
		    log_dbg("redir completed");
		    redir_conn_finish(&requests[idx].conn, &requests[idx]);
		    break;
		  }
		}
	      }
	      break;
	    } /* switch(net_select_read_fd()) */
	  }
	}
      }
      
      break;
    }
  }

  redir_free(redir);

  selfpipe_finish();
  
  return 0;
}
