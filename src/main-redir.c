/* 
 * Copyright (C) 2009 Coova Technologies, LLC. <support@coova.com>
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

#ifndef USING_IPC_UNIX
#error This requires the UNIX IPC method
#endif

typedef struct _redir_request {
  int index;
  
  char inuse:1;
  
  bstring url;
  bstring data;
  bstring post;
  bstring wbuf;

  struct conn_t conn;
  
  int socket_fd;

  struct _redir_request *prev, *next;
  
} redir_request;

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

static void close_request(redir_request *req) {
  log_dbg("closing request");
  req->inuse = 0;
  req->socket_fd = 0;
  if (requests_free) {
    requests_free->prev = req;
    req->next = requests_free;
  }
  requests_free = req;
}

static int 
sock_redir_getstate(struct redir_t *redir, 
		    struct sockaddr_in *address,
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
  msg.mdata.addr = address->sin_addr;

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
  conn_close(&req->conn);
  if (req->socket_fd) {
    close(req->socket_fd);
  }
  close_request(req);
  return 0;
}

static int redir_conn_read(struct conn_t *conn, void *ctx) {
  redir_request *req = (redir_request *)ctx;
  char b[PKT_MAX_LEN];
  int r = read(conn->sock, b, sizeof(b));

  /*log_dbg("read: %d", r);*/

  if (r <= 0) {
    redir_conn_finish(conn, ctx);
  } else if (r > 0) {
    int w = write(req->socket_fd, b, r);
    /*log_dbg("write: %d", w);*/
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
		 void *ctx) {
  redir_request *req = get_request();
  int port = 80;
  int i;

  if (!req) return 1;

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
      req->socket_fd = socket->fd[1];
      if (!req->wbuf) req->wbuf = bfromcstr("");
      bassign(req->wbuf, httpreq->data_in);
      
      if (conn_setup(&req->conn, httpreq->host, port, req->wbuf)) {
	log_err(errno, "conn_setup()");
	return -1;
      }
      
      conn_set_readhandler(&req->conn, redir_conn_read, req);
      conn_set_donehandler(&req->conn, redir_conn_finish, req);
      return 0;
    }
  }

  return 1;
}

static unsigned char redir_radius_id=0;

int redir_accept2(struct redir_t *redir, int idx) {
  int status;
  int new_socket;
  struct sockaddr_in address;
  socklen_t addrlen;
  char buffer[128];
  int flags;

  addrlen = sizeof(struct sockaddr_in);

  if ((new_socket = accept(redir->fd[idx], (struct sockaddr *)&address, &addrlen)) < 0) {
    if (errno != ECONNABORTED)
      log_err(errno, "accept()");

    return 0;
  }

  flags = fcntl(new_socket, F_GETFL, 0);
  if (flags < 0) flags = 0;

#ifdef O_NDELAY
  flags |= O_NDELAY;
#endif
  
  if (fcntl(new_socket, F_SETFL, flags) < 0) {
    log_err(errno, "could not set socket flags");
  }
  
  redir_radius_id++;

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
    
    return redir_main(redir, new_socket, new_socket, &address, idx, 0);

  }

  return 0;
}

int main(int argc, char **argv) {
  int maxfd = 0;
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;

  int status;
  int idx;
  int active_last = 0;
  int active = 0;

  struct redir_t *redir;

  int keep_going = 1;
  int reload_config = 0;

  uint8_t hwaddr[6], mac[32];
  struct ifreq ifr;
  
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  options_init();

  chilli_signals(&keep_going, &reload_config);
  
  process_options(argc, argv, 1);
  
  strncpy(ifr.ifr_name, _options.dhcpif, sizeof(ifr.ifr_name));
  
  if (ioctl(fd, SIOCGIFHWADDR, (caddr_t)&ifr) == 0) {
    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, PKT_ETH_ALEN);
    
    snprintf(mac, sizeof(mac), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", 
	     hwaddr[0], hwaddr[1], hwaddr[2],
	     hwaddr[3], hwaddr[4], hwaddr[5]);
    
    _options.nasmac = strdup(mac);
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

  if (redir->fd[0] > maxfd) maxfd = redir->fd[0];
  if (redir->fd[1] > maxfd) maxfd = redir->fd[1];
  redir_set(redir, hwaddr, (_options.debug));
  redir_set_cb_getstate(redir, sock_redir_getstate);

  redir->cb_handle_url = redir_handle_url;
  redir->cb_handle_url_ctx = 0;

  while (keep_going) {
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    active = 0;

    if (reload_config) {
      reload_options(argc, argv);
      reload_config = 0;

      redir_set(redir, hwaddr, _options.debug);
    }

    if (redir->fd[0])
      fd_set(redir->fd[0], &fdread);

    if (redir->fd[1])
      fd_set(redir->fd[1], &fdread);

    for (idx=0; idx < max_requests; idx++) {
      conn_fd(&requests[idx].conn, &fdread, &fdwrite, &fdexcep, &maxfd);
      if (requests[idx].inuse && requests[idx].socket_fd) {
	int fd = requests[idx].socket_fd;
	if (fd > maxfd) maxfd = fd;
	fd_set(fd, &fdread);
	active++;
      }
    }

    /*
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
    */

    if (active != active_last) {
      log_info("active connections: %d", active);
      active_last = active;
    }

    status = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, NULL/*&timeout*/);

    switch (status) {
    case -1:
      if (EINTR != errno) {
	log_err(errno, "select() returned -1!");
      }
      break;  

    case 0:
      break;

    default:
      if (status > 0) {

	if (redir->fd[0])
	  if (fd_isset(redir->fd[0], &fdread) && redir_accept2(redir, 0) < 0)
	    log_err(0, "redir_accept() failed!");

	if (redir->fd[1])
	  if (fd_isset(redir->fd[1], &fdread) && redir_accept2(redir, 1) < 0)
	    log_err(0, "redir_accept() failed!");

	for (idx=0; idx < max_requests; idx++) {
	  conn_update(&requests[idx].conn, &fdread, &fdwrite, &fdexcep);
	  if (requests[idx].inuse && requests[idx].socket_fd) {
	    int fd = requests[idx].socket_fd;
	    if (FD_ISSET(fd, &fdread)) {
	      char b[1500];
	      int r;

#ifdef HAVE_SSL
#endif
	      r = read(fd, b, sizeof(b));

	      /*log_dbg("read: %d", r);*/
	      
	      if (r <= 0) {
		redir_conn_finish(&requests[idx].conn, &requests[idx]);
	      } else if (r > 0) {
		int w = write(requests[idx].conn.sock, b, r);
		/*log_dbg("write: %d", w);*/
		if (r != w) {
		  log_err(errno, "problem writing what we read");
		  redir_conn_finish(&requests[idx].conn, &requests[idx]);
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
