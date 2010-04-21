/* 
 * Copyright (C) 2010 Coova Technologies, LLC. <support@coova.com>
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

#include "system.h"
#include "syserr.h"
#include "cmdline.h"
#include "dhcp.h"
#include "redir.h"
#include "radius.h"
#include "chilli.h"
#include "options.h"
#include "cmdsock.h"
#include "md5.h"
#include "conn.h"

struct options_t _options;

static select_ctx sctx;

#ifndef USING_IPC_UNIX
#error This requires the UNIX IPC method
#endif

static int max_requests = 0;
static redir_request * requests = 0;
static redir_request * requests_free = 0;

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

  req->state = 0;
  req->next = req->prev = 0;
  req->inuse = 1;
  return req;
}

static void close_request(redir_request *req) {
  log_dbg("closing request");
  req->inuse = 0;
  req->proxy = 0;
  req->socket_fd = 0;
  req->state = 0;
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

  char *statedir = _options.statedir ? _options.statedir : DEFSTATEDIR;
  char filedest[512];

  snprintf(filedest, sizeof(filedest), "%s/%s", statedir, 
	   _options.unixipc ? _options.unixipc : "chilli.ipc");

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
    log_err(errno, "could not read from %s", remote.sun_path);
    close(s);
    return -1;
  }

  close(s);

  return conn->s_state.authenticated == 1;
}

static int redir_conn_finish(struct conn_t *conn, void *ctx) {
  redir_request *req = (redir_request *)ctx;
#ifdef HAVE_SSL
  if (req->sslcon) {
    openssl_shutdown(req->sslcon, 2);
    openssl_free(req->sslcon);
    req->sslcon=0;
  }
#endif
  if (req->conn.sock) {
    if (req->state & REDIR_CONN_FD) {
      net_select_rmfd(&sctx, req->conn.sock);
    }
    conn_close(&req->conn);
  }
  if (req->socket_fd) {
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
  char b[PKT_MAX_LEN];

  int r = read(conn->sock, b, sizeof(b));

  log_dbg("conn_read: %d", r);

  if (r <= 0) {
    redir_conn_finish(conn, ctx);
  } else if (r > 0) {
    int w;
    req->last_active = mainclock_tick();
    w = write(req->socket_fd, b, r);
    log_dbg("write: %d", w);
    if (r != w) {
      log_err(errno, "problem writing what we read");
      redir_conn_finish(conn, ctx);
    }
  }
  return 0;
}

static int
check_regex(regex_t *re, char *regex, char *s) {
  int ret;

  log_dbg("Checking %s =~ %s", s, regex);
  
  if (!re->allocated) {
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

  for (i=0; i < MAX_REGEX_PASS_THROUGHS; i++) {
    
    int matches = 1;

    if ( ! _options.regex_pass_throughs[i].regex_host[0] &&
	 ! _options.regex_pass_throughs[i].regex_path[0] &&
	 ! _options.regex_pass_throughs[i].regex_qs[0] )
      break;

    log_dbg("REGEX host=[%s] path=[%s] qs=[%s]",
	    _options.regex_pass_throughs[i].regex_host,
	    _options.regex_pass_throughs[i].regex_path,
	    _options.regex_pass_throughs[i].regex_qs);

    log_dbg("Host %s", httpreq->host);

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

    if (matches) {
      req->proxy = 1;
      
      if (conn_setup(&req->conn, httpreq->host, port, req->wbuf)) {
	log_err(errno, "conn_setup()");
	return -1;
      }

      req->state |= REDIR_CONN_FD;
      net_select_addfd(&sctx, req->conn.sock, SELECT_READ);
      
      return 0;
    }
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
  int flags;

  addrlen = sizeof(struct sockaddr_in);

  if ((new_socket = accept(redir->fd[idx], (struct sockaddr *)&address, &addrlen)) < 0) {
    if (errno != ECONNABORTED)
      log_err(errno, "accept()");

    return 0;
  }

  addrlen = sizeof(struct sockaddr_in);

  if (getsockname(new_socket, (struct sockaddr *)&baddress, &addrlen) < 0) {
    log_warn(errno, "getsockname() failed!");
  }

  flags = fcntl(new_socket, F_GETFL, 0);
  if (flags < 0) flags = 0;

#ifdef O_NDELAY
  flags |= O_NDELAY;
#endif
  
  if (fcntl(new_socket, F_SETFL, flags) < 0) {
    log_err(errno, "could not set socket flags");
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
    
    snprintf(buffer,sizeof(buffer)-1,"%s",inet_ntoa(address.sin_addr));
    setenv("TCPREMOTEIP",buffer,1);
    setenv("REMOTE_ADDR",buffer,1);
    snprintf(buffer,sizeof(buffer)-1,"%d",ntohs(address.sin_port));
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
    if (!req->wbuf) req->wbuf = bfromcstr("");
    else bassigncstr(req->wbuf, "");

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
  
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  options_init();

  chilli_signals(&keep_going, &reload_config);
  
  process_options(argc, argv, 1);
  
  strncpy(ifr.ifr_name, _options.dhcpif, sizeof(ifr.ifr_name));
  
  if (ioctl(fd, SIOCGIFHWADDR, (caddr_t)&ifr) == 0) {
    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, PKT_ETH_ALEN);
  } else {
    log_err(errno, "could not get MAC address");
    return -1;
  }
  
  close(fd);
  
  /* create an instance of redir */
  if (redir_new(&redir, &_options.uamlisten, _options.uamport, _options.uamuiport)) {
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

  /* epoll */
  net_select_addfd(&sctx, redir->fd[0], SELECT_READ);
  net_select_addfd(&sctx, redir->fd[1], SELECT_READ);

  while (keep_going) {

    /* select/poll */
    net_select_zero(&sctx);
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
	
	if (_options.debug) {
	  struct sockaddr_in address;
	  socklen_t addrlen = sizeof(address);
	  
	  if (getpeername(requests[idx].socket_fd, (struct sockaddr *)&address, &addrlen) >= 0) {
	    char line[512];
	    
	    snprintf(line, sizeof(line),
		     "#%d (%d) %d connection from %s %d",
		     timeout ? -1 : active, fd, (int) requests[idx].last_active,
		     inet_ntoa(address.sin_addr),
		     ntohs(address.sin_port));
	    
	    if (requests[idx].conn.sock) {
	      addrlen = sizeof(address);
	      if (getpeername(requests[idx].conn.sock, (struct sockaddr *)&address, &addrlen) >= 0) {
		snprintf(line+strlen(line), sizeof(line)-strlen(line),
			 " to %s %d",
			 inet_ntoa(address.sin_addr),
			 ntohs(address.sin_port));
	      }
	    }
	    
	    if (timeout) {
	      snprintf(line+strlen(line), sizeof(line)-strlen(line),
		       " (timeout)");
	    }

	    log_dbg("%s", line);
	  }
	}
      }
    }

    if (active != active_last) {
      log_dbg("active connections: %d", active);
      active_last = active;
    }
    
    status = net_select(&sctx);
    
    log_dbg("epoll %d", status);
    if (status > 0) {
      int i;
      for (i=0; i < status; i++) {
	log_dbg("epoll fd %d %d", sctx.events[i].data.fd, sctx.events[i].events);
      }
    }
    /*
    */

    switch (status) {
    case -1:
      if (EINTR != errno) {
	log_err(errno, "select() returned -1!");
      }
      break;  

    default:
      if (status > 0) {
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
	      if (openssl_check_accept(requests[idx].sslcon) < 0) {
		redir_conn_finish(&requests[idx].conn, &requests[idx]);
		continue;
	      }
	    }
#endif
	    
	    if (net_select_read_fd(&sctx, fd)) {
	      
	      if (requests[idx].proxy) {
		char b[1500];
		int r;
		
#ifdef HAVE_SSL
		if (requests[idx].sslcon) {
		  /*
		  log_dbg("proxy_read_ssl");
		  */
		  r = openssl_read(requests[idx].sslcon, 
				   b, sizeof(b), 0);
		} else
#endif
		  r = recv(fd, b, sizeof(b), 0);
		
		/*
		log_dbg("proxy_read: %d %d", fd, r);
		*/
		
		if (r <= 0) {
		  
		  redir_conn_finish(&requests[idx].conn, &requests[idx]);
		  
		} else if (r > 0) {
		  
		  int w;
		  requests[idx].last_active = mainclock_tick();
		  w = write(requests[idx].conn.sock, b, r);
		  
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
#ifdef HAVE_SSL
		  if (requests[idx].sslcon && openssl_pending(requests[idx].sslcon) > 0)
		    goto go_again;
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
	  }
	}
      }
      
      break;
    }
  }

  return 0;
}
