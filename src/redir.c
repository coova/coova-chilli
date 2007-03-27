/*
 *
 * HTTP redirection functions.
 * Copyright (C) 2004, 2005 Mondru AB.
 * Copyright (c) 2006 Coova Technologies Ltd
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 *
 */

#include "system.h"
#include "syserr.h"
#include "radius.h"
#include "radius_wispr.h"
#include "radius_chillispot.h"
#include "redir.h"
#include "md5.h"
#include "dhcp.h"
#include "chilli.h"
#include "options.h"

static int optionsdebug = 0; /* TODO: Should be changed to instance */

static int keep_going = 1;   /* OK as global variable for child process */

static int termstate = REDIR_TERM_INIT;    /* When we were terminated */

char credits[] =
"<H1>ChilliSpot " VERSION "</H1>"
"<p>Copyright 2002-2005 Mondru AB</p>"
"<p>Copyright 2006-2007 <a href=\"http://coova.org/\">Coova Technologies Ltd</a></p>"
"ChilliSpot is an Open Source captive portal or wireless LAN access point "
"controller developed by the community at "
"<a href=\"http://coova.org\">coova.org</a> and "
"<a href=\"http://www.chillispot.org\">www.chillispot.org</a>. It is licensed "
"under the GPL.</p><p>ChilliSpot acknowledges all community members, "
"especially those mentioned at "
"<a href=\"http://www.chillispot.org/credits.html\">http://www.chillispot.org/credits.html</a>.";

struct redir_socket{int fd[2];};

/* Termination handler for clean shutdown */
static void redir_termination(int signum) {
  if (optionsdebug) log_dbg("Terminating redir client!\n");
  keep_going = 0;
}

/* Alarm handler for ensured shutdown */
static void redir_alarm(int signum) {
  log_warn(0, "Client process timed out: %d", termstate);
  exit(0);
}

/* Generate a 16 octet random challenge */
static int redir_challenge(unsigned char *dst) {
  FILE *file;

  if ((file = fopen("/dev/urandom", "r")) == NULL) {
    log_err(errno, "fopen(/dev/urandom, r) failed");
    return -1;
  }
  
  if (fread(dst, 1, REDIR_MD5LEN, file) != REDIR_MD5LEN) {
    log_err(errno, "fread() failed");
    return -1;
  }
  
  fclose(file);
  return 0;
}

/* Convert 32+1 octet ASCII hex string to 16 octet unsigned char */
static int redir_hextochar(char *src, unsigned char * dst) {
  char x[3];
  int n;
  int y;
  
  for (n=0; n< REDIR_MD5LEN; n++) {
    x[0] = src[n*2+0];
    x[1] = src[n*2+1];
    x[2] = 0;
    if (sscanf (x, "%2x", &y) != 1) {
      log_err(0, "HEX conversion failed!");
      return -1;
    }
    dst[n] = (unsigned char) y;
  }

  return 0;
}

/* Convert 16 octet unsigned char to 32+1 octet ASCII hex string */
static int redir_chartohex(unsigned char *src, char *dst) {

  char x[3];
  int n;
  
  for (n=0; n<REDIR_MD5LEN; n++) {
    snprintf(x, 3, "%.2x", src[n]);
    dst[n*2+0] = x[0];
    dst[n*2+1] = x[1];
  }
  dst[REDIR_MD5LEN*2] = 0;
  return 0;
}

static int redir_xmlencode(char *src, int srclen, char *dst, int dstsize) {
  char *x;
  int n;
  int i = 0;
  
  for (n=0; n<srclen; n++) {
    x=0;
    switch(src[n]) {
    case '&':  x = "&amp;";  break;
    case '\"': x = "&quot;"; break;
    case '<':  x = "&lt;";   break;
    case '>':  x = "&gt;";   break;
    default:
      if (i < dstsize - 1) dst[i++] = src[n];
      break;
    }
    if (x) {
      if (i < dstsize - strlen(x)) {
	strncpy(dst + i, x, strlen(x));
	i += strlen(x);
      }
    }
  }
  dst[i] = 0;
  return 0;
}

/* Encode src as urlencoded and place null terminated result in dst */
static int redir_urlencode(char *src, int srclen, char *dst, int dstsize) {
  char x[3];
  int n;
  int i = 0;
  
  for (n=0; n<srclen; n++) {
    if ((('A' <= src[n]) && (src[n] <= 'Z')) ||
	(('a' <= src[n]) && (src[n] <= 'z')) ||
	(('0' <= src[n]) && (src[n] <= '9')) ||
	('-' == src[n]) ||
	('_' == src[n]) ||
	('.' == src[n]) ||
	('!' == src[n]) ||
	('~' == src[n]) ||
	('*' == src[n]) ||
	('\'' == src[n]) ||
	('(' == src[n]) ||
	(')' == src[n])) {
      if (i<dstsize-1) {
	dst[i++] = src[n];
      }
    }
    else {
      snprintf(x, 3, "%.2x", src[n]);
      if (i<dstsize-3) {
	dst[i++] = '%';
	dst[i++] = x[0];
	dst[i++] = x[1];
      }
    }
  }
  dst[i] = 0;
  return 0;
}

/* Decode urlencoded src and place null terminated result in dst */
static int redir_urldecode(char *src, int srclen, char *dst, int dstsize) {
  char x[3];
  int n = 0;
  int i = 0;
  unsigned int c;

  while (n<srclen) {
    if (src[n] == '%') {
      if ((n+2) < srclen) {
	x[0] = src[n+1];
	x[1] = src[n+2];
	x[2] = 0;
	c = '_';
	sscanf(x, "%x", &c);
	if (i<(dstsize-1)) dst[i++] = c; 
      }
      n += 3;
    }
    else {
      if (i<(dstsize-1)) dst[i++] = src[n];
      n++;
    }
  }
  dst[i] = 0;
  return 0;
}

/* Concatenate src to dst and place result dst */
static int redir_stradd(char *dst, int dstsize, char *fmt, ...) {
  va_list args;
  char buf[REDIR_MAXBUFFER];

  va_start(args, fmt);
  vsnprintf(buf, REDIR_MAXBUFFER, fmt, args);
  va_end(args);

  buf[REDIR_MAXBUFFER-1] = 0; 
  if ((strlen(dst) + strlen(buf)) > dstsize-1) {
    log_err(0, "redir_stradd() failed");
    return -1;
  }

  strcpy(dst + strlen(dst), buf);
  return 0;
}


/* Make an XML Reply */
static int redir_xmlreply(struct redir_t *redir, 
			  struct redir_conn_t *conn, int res, long int timeleft, char* hexchal, 
			  char* reply, char* redirurl, 
			  char *dst, int dstsize) {
  if (redir->no_uamwispr && !(redir->chillixml)) return 0;

  snprintf(dst, dstsize,
	   "<!--\r\n"
	   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n");

  if (!redir->no_uamwispr) {
    redir_stradd(dst, dstsize, 
		 "<WISPAccessGatewayParam\r\n"
		 "  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n"
		 "  xsi:noNamespaceSchemaLocation=\"http://www.acmewisp.com/WISPAccessGatewayParam.xsd\""
		 ">\r\n");
  switch (res) {
  case REDIR_ALREADY:
    redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
    redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
    redir_stradd(dst, dstsize, "<ResponseCode>102</ResponseCode>\r\n");
    redir_stradd(dst, dstsize, "<ReplyMessage>Already logged on</ReplyMessage>\r\n");
    redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
    break;
  case REDIR_FAILED_REJECT:
    redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
    redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
    redir_stradd(dst, dstsize, "<ResponseCode>100</ResponseCode>\r\n");
    if (reply) {
      redir_stradd(dst, dstsize, "<ReplyMessage>%s</ReplyMessage>\r\n", reply);
    }
    else {
      redir_stradd(dst, dstsize, 
		   "<ReplyMessage>Invalid Password</ReplyMessage>\r\n");
    }
    redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
    break;
  case REDIR_FAILED_OTHER:
    redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
    redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
    redir_stradd(dst, dstsize, "<ResponseCode>102</ResponseCode>\r\n");
    if (reply) {
      redir_stradd(dst, dstsize, "<ReplyMessage>%s</ReplyMessage>\r\n", reply);
    }
    else {
      redir_stradd(dst, dstsize, 
		   "<ReplyMessage>Radius error</ReplyMessage>\r\n");
    }
    redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
    break;
  case REDIR_SUCCESS:
    redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
    redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
    redir_stradd(dst, dstsize, "<ResponseCode>50</ResponseCode>\r\n");
    if (reply) {
      redir_stradd(dst, dstsize, "<ReplyMessage>%s</ReplyMessage>\r\n", reply);
    }
    redir_stradd(dst, dstsize,
		 "<LogoffURL>http://%s:%d/logoff</LogoffURL>\r\n",
		 inet_ntoa(redir->addr), redir->port);
    if (redirurl) {
      redir_stradd(dst, dstsize,
		   "<RedirectionURL>%s</RedirectionURL>\r\n", redirurl);
    }
    redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
    break;
  case REDIR_LOGOFF:
    redir_stradd(dst, dstsize, "<LogoffReply>\r\n");
    redir_stradd(dst, dstsize, "<MessageType>130</MessageType>\r\n");
    redir_stradd(dst, dstsize, "<ResponseCode>150</ResponseCode>\r\n");
    redir_stradd(dst, dstsize, "</LogoffReply>\r\n");
    break;
  case REDIR_NOTYET:
    redir_stradd(dst, dstsize, "<Redirect>\r\n");
    redir_stradd(dst, dstsize, "<AccessProcedure>1.0</AccessProcedure>\r\n");
    if (redir->radiuslocationid) {
      redir_stradd(dst, dstsize, 
		   "<AccessLocation>%s</AccessLocation>\r\n",
		   redir->radiuslocationid);
    }
    if (redir->radiuslocationname) {
      redir_stradd(dst, dstsize, 
	       "<LocationName>%s</LocationName>\r\n",
	       redir->radiuslocationname);
    }
    redir_stradd(dst, dstsize, 
    		 "<LoginURL>%s?res=smartclient&amp;uamip=%s&amp;uamport=%d&amp;challenge=%s</LoginURL>\r\n",
    		 redir->url, inet_ntoa(redir->addr), redir->port, hexchal); 
    redir_stradd(dst, dstsize, 
		 "<AbortLoginURL>http://%s:%d/abort</AbortLoginURL>\r\n",
		 inet_ntoa(redir->addr), redir->port);
    redir_stradd(dst, dstsize, "<MessageType>100</MessageType>\r\n");
    redir_stradd(dst, dstsize, "<ResponseCode>0</ResponseCode>\r\n");
    redir_stradd(dst, dstsize, "</Redirect>\r\n");
    break;
  case REDIR_ABORT_ACK:
    redir_stradd(dst, dstsize, "<AbortLoginReply>\r\n");
    redir_stradd(dst, dstsize, "<MessageType>150</MessageType>\r\n");
    redir_stradd(dst, dstsize, "<ResponseCode>151</ResponseCode>\r\n");
    redir_stradd(dst, dstsize, "</AbortLoginReply>\r\n");
    break;
  case REDIR_ABORT_NAK:
    redir_stradd(dst, dstsize, "<AbortLoginReply>\r\n");
    redir_stradd(dst, dstsize, "<MessageType>150</MessageType>\r\n");
    redir_stradd(dst, dstsize, "<ResponseCode>50</ResponseCode>\r\n");
    redir_stradd(dst, dstsize,
		 "<LogoffURL>http://%s:%d/logoff</LogoffURL>\r\n",
		 inet_ntoa(redir->addr), redir->port);
    redir_stradd(dst, dstsize, "</AbortLoginReply>\r\n");
    break;
  case REDIR_STATUS:
    redir_stradd(dst, dstsize, "<AuthenticationPollReply>\r\n");
    redir_stradd(dst, dstsize, "<MessageType>140</MessageType>\r\n");
    if (conn->authenticated != 1) {
      redir_stradd(dst, dstsize, "<ResponseCode>150</ResponseCode>\r\n");
      redir_stradd(dst, dstsize,
                  "<ReplyMessage>Not logged on</ReplyMessage>\r\n");
    }
    else {
      redir_stradd(dst, dstsize, "<ResponseCode>50</ResponseCode>\r\n");
      redir_stradd(dst, dstsize,
                  "<ReplyMessage>Already logged on</ReplyMessage>\r\n");
    }
    redir_stradd(dst, dstsize, "</AuthenticationPollReply>\r\n");
    break;
  default:
    log_err(0, "Unknown res in switch");
    return -1;
  }
  redir_stradd(dst, dstsize, "</WISPAccessGatewayParam>\r\n");
  }

  if (redir->chillixml) {
    redir_stradd(dst, dstsize, "<ChilliSpotSession>\r\n");
    switch (res) {
    case REDIR_NOTYET:
      redir_stradd(dst, dstsize, "<Challenge>%s</Challenge>\r\n", hexchal) ;
      break;
    case REDIR_STATUS:
      if (conn->authenticated == 1) {
        struct timeval timenow;
        uint32_t sessiontime;
        gettimeofday(&timenow, NULL);
        sessiontime = timenow.tv_sec - conn->start_time.tv_sec;
        sessiontime += (timenow.tv_usec - conn->start_time.tv_usec) / 1000000;

        redir_stradd(dst, dstsize, "<State>1</State>\r\n");
        redir_stradd(dst, dstsize, "<StartTime>%d</StartTime>\r\n" , conn->start_time);
        redir_stradd(dst, dstsize, "<SessionTime>%d</SessionTime>\r\n", sessiontime);
        if (timeleft) {
         redir_stradd(dst, dstsize, "<TimeLeft>%d</TimeLeft>\r\n",
                      timeleft);
        }
        redir_stradd(dst, dstsize, "<Timeout>%d</Timeout>\r\n",
                    conn->params.sessiontimeout);
        redir_stradd(dst, dstsize, "<InputOctets>%d</InputOctets>\r\n",
                    conn->input_octets);
        redir_stradd(dst, dstsize, "<OutputOctets>%d</OutputOctets>\r\n",
                    conn->output_octets);
        redir_stradd(dst, dstsize, "<MaxInputOctets>%d</MaxInputOctets>\r\n",
                    conn->params.maxinputoctets);
        redir_stradd(dst, dstsize, "<MaxOutputOctets>%d</MaxOutputOctets>\r\n",
                    conn->params.maxoutputoctets);
        redir_stradd(dst, dstsize, "<MaxTotalOctets>%d</MaxTotalOctets>\r\n",
                    conn->params.maxtotaloctets);
      }
      else {
        redir_stradd(dst, dstsize, "<State>0</State>\r\n");

      }
      break;
    case REDIR_ALREADY:
      redir_stradd(dst, dstsize, "<Already>1</Already>\r\n");
      break;
    case REDIR_FAILED_REJECT:
    case REDIR_FAILED_OTHER:
      if (reply) {
        redir_stradd(dst, dstsize, "<ReplyMessage>%s</ReplyMessage>\r\n", reply);
      }
      redir_stradd(dst, dstsize, "<State>0</State>\r\n");
      break;
    case REDIR_SUCCESS:
      if (reply) {
	redir_stradd(dst, dstsize, "<ReplyMessage>%s</ReplyMessage>\r\n", reply);
      }
      redir_stradd(dst, dstsize, "<State>1</State>\r\n");
    break;
    case REDIR_LOGOFF:
      redir_stradd(dst, dstsize, "<State>0</State>\r\n");
      break;
    case REDIR_ABORT_ACK:
      redir_stradd(dst, dstsize, "<Abort_ack>1</Abort_ack>\r\n");
      break;
    case REDIR_ABORT_NAK:
      redir_stradd(dst, dstsize, "<Abort_nak>1</Abort_nak>\r\n");
      break;
    default:
      log_err(0, "Unknown res in switch");
      return -1;
    }
    redir_stradd(dst, dstsize, "</ChilliSpotSession>\r\n");  
  }
  
  redir_stradd(dst, dstsize, "-->\r\n");
  return 0;
}

static int redir_buildurl(struct redir_conn_t *conn, char *buffer, int buflen,
			  struct redir_t *redir, char *resp,
			  long int timeleft, char* hexchal, char* uid, 
			  char* userurl, char* reply, char* redirurl,
			  uint8_t *hismac, struct in_addr *hisip) {
  char b[512];

  snprintf(buffer, buflen, "%s?res=%s&uamip=%s&uamport=%d", 
	   redir->url, resp, inet_ntoa(redir->addr), redir->port);

  buffer[buflen-1] = 0;

  if (hexchal) {
    if (redir_stradd(buffer, buflen, "&challenge=%s", hexchal) == -1) return -1;
  }
  
  if (uid) {
    b[0] = 0;
    (void)redir_urlencode(uid, strlen(uid), b, sizeof(b));
    if (redir_stradd(buffer, buflen, "&uid=%s", b) == -1) return -1;
  }

  {/* maybe make optional */
    int starttime = conn->start_time.tv_sec;
    if (starttime) {
      int sessiontime;
      struct timeval timenow;
      gettimeofday(&timenow, NULL);
      sessiontime = timenow.tv_sec - starttime;
      redir_stradd(buffer, buflen, "&starttime=%ld", starttime);
      redir_stradd(buffer, buflen, "&sessiontime=%ld", sessiontime);
    }
    if (conn->params.sessiontimeout) 
      redir_stradd(buffer, buflen, "&sessiontimeout=%ld", conn->params.sessiontimeout);
    if (conn->params.sessionterminatetime)
      redir_stradd(buffer, buflen, "&stoptime=%ld", conn->params.sessionterminatetime);
  }
 
  if (timeleft) {
    if (redir_stradd(buffer, buflen, "&timeleft=%ld", timeleft) == -1) return -1;
  }
  
  if (hismac) {
    char mac[REDIR_MACSTRLEN+1];
    b[0] = 0;
    snprintf(mac, REDIR_MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	     hismac[0], hismac[1],
	     hismac[2], hismac[3],
	     hismac[4], hismac[5]);
    (void)redir_urlencode(mac, strlen(mac), b, sizeof(b));
    if (redir_stradd(buffer, buflen, "&mac=%s", b) == -1) return -1;
  }

  if (hisip) {
    if (redir_stradd(buffer, buflen, "&ip=%s", inet_ntoa(*hisip)) == -1) return -1;
  }

  if (reply) {
    b[0] = 0;
    (void)redir_urlencode(reply, strlen(reply), b, sizeof(b));
    if (redir_stradd(buffer, buflen, "&reply=%s", b) == -1) return -1;
  }

  if (redir->ssid) {
    b[0] = 0;
    (void)redir_urlencode(redir->ssid, strlen(redir->ssid), b, sizeof(b));
    if (redir_stradd(buffer, buflen, "&ssid=%s", b) == -1) return -1;
  }

  if (redir->nasmac) {
    b[0] = 0;
    (void)redir_urlencode(redir->nasmac, strlen(redir->nasmac), b, sizeof(b));
    if (redir_stradd(buffer, buflen, "&called=%s", b) == -1) return -1;
  }

  if (redir->radiusnasid) {
    b[0] = 0;
    (void)redir_urlencode(redir->radiusnasid, strlen(redir->radiusnasid), b, sizeof(b));
    if (redir_stradd(buffer, buflen, "&nasid=%s", b) == -1) return -1;
  }

  if (redirurl) {
    b[0] = 0;
    (void)redir_urlencode(redirurl, strlen(redirurl), b, sizeof(b));
    if (redir_stradd(buffer, buflen, "&redirurl=%s", b) == -1) return -1;
  }

  if (userurl) {
    b[0] = 0;
    (void)redir_urlencode(userurl, strlen(userurl), b, sizeof(b));
    if (redir_stradd(buffer, buflen, "&userurl=%s", b) == -1) return -1;
  }

  return 0;
}

int 
tcp_write_timeout(int timeout, struct redir_socket *sock, char *buf, int len) {
  fd_set fdset;
  struct timeval tv;
  int fd = sock->fd[1];

  FD_ZERO(&fdset);
  FD_SET(fd,&fdset);

  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  if (select(fd + 1,(fd_set *) 0,&fdset,(fd_set *) 0,&tv) == -1)
    return -1;

  if (FD_ISSET(fd, &fdset))
#if WIN32
    return send(fd,buf,len,0);
#else
    return write(fd,buf,len);
#endif

  return -1;
}

static int timeout = 10;

int
tcp_write(struct redir_socket *sock, char *buf, int len) {
  int c, r = 0;
  while (r < len) {
    c = tcp_write_timeout(timeout,sock,buf+r,len-r);
    if (c <= 0) return r;
    r += c;
  }
  return r;
}

/* Make an HTTP redirection reply and send it to the client */
static int redir_reply(struct redir_t *redir, struct redir_socket *sock, 
		       struct redir_conn_t *conn, int res, char *url,
		       long int timeleft, char* hexchal, char* uid, 
		       char* userurl, char* reply, char* redirurl,
		       uint8_t *hismac, struct in_addr *hisip) {
  char buffer[5120];
  char urlb[2048];
  char *resp = NULL;

  buffer[0] = 0;
  switch (res) {
  case REDIR_ALREADY:
    resp = "already";
    break;
  case REDIR_FAILED_REJECT:
  case REDIR_FAILED_OTHER:
    resp = "failed";
    break;
  case REDIR_SUCCESS:
    resp = "success";
    break;
  case REDIR_LOGOFF:
    resp = "logoff";
    break;
  case REDIR_NOTYET:
    resp = "notyet";
    break;
  case REDIR_ABORT_ACK:
    resp = "logoff";
    break;
  case REDIR_ABORT_NAK:
    resp = "already";
    break;
  case REDIR_ABOUT:
    break;
  case REDIR_STATUS:
    if (conn->authenticated == 1)
      resp = "already";
    else
      resp = "notyet";
    break;
  default:
    log_err(0, "Unknown res in switch");
    return -1;
  }

  if (resp) {
    if (!url) {
      if (redir_buildurl(conn, urlb, sizeof(urlb), redir, resp, timeleft, hexchal, 
			 uid, userurl, reply, redirurl, hismac, hisip) == -1) return -1;
      url = urlb;
    }

    snprintf(buffer, sizeof(buffer), 
	     "HTTP/1.0 302 Moved Temporarily\r\n"
	     "Location: %s\r\n\r\n"
	     "<HTML><BODY><H2>Browser error!</H2>"
	     "Browser does not support redirects!</BODY>\r\n"
	     "<!--\r\n", url);

    if (tcp_write(sock, buffer, strlen(buffer)) < 0) {
      log_err(errno, "tcp_write() failed!");
      return -1;
    }

    buffer[0] = 0;
    redir_xmlreply(redir, conn, res, timeleft, hexchal, reply, 
		   redirurl, buffer, sizeof(buffer));

    if (tcp_write(sock, buffer, strlen(buffer)) < 0) {
      log_err(errno, "tcp_write() failed!");
      return -1;
    }

    buffer[0] = 0;
    snprintf(buffer, sizeof(buffer), "\r\n-->\r\n</HTML>\r\n");

    if (tcp_write(sock, buffer, strlen(buffer)) < 0) {
      log_err(errno, "tcp_write() failed!");
      return -1;
    }
  }
  else {
    snprintf(buffer, sizeof(buffer)-1, 
	     "HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n"
	     "<HTML><HEAD><TITLE>(Coova-)ChilliSpot</TITLE></HEAD><BODY>%s</BODY></HTML>\r\n", 
	     credits);
    if (tcp_write(sock, buffer, strlen(buffer)) < 0) {
      log_err(errno, "tcp_write() failed!");
      return -1;
    }
  }

  if (strstr(conn->useragent, "Flash")) {
    buffer[0] = 0;
    if (tcp_write(sock, buffer, 1) < 0) {
      log_err(errno, "tcp_write() failed!");
      return -1;
    }
  }
  
  return 0;
}

/* Allocate new instance of redir */
int redir_new(struct redir_t **redir,
	      struct in_addr *addr, int port, int uiport) {
  struct sockaddr_in address;
  int optval = 1;
  int n = 0;

  if (!(*redir = calloc(1, sizeof(struct redir_t)))) {
    log_err(errno, "calloc() failed");
    return EOF;
  }

  (*redir)->addr = *addr;
  (*redir)->port = port;
  (*redir)->uiport = uiport;
  (*redir)->starttime = 0;
  
  if (((*redir)->fd[0] = socket(AF_INET ,SOCK_STREAM ,0)) < 0) {
    log_err(errno, "socket() failed");
    return -1;
  }

  if (uiport && ((*redir)->fd[1] = socket(AF_INET ,SOCK_STREAM ,0)) < 0) {
    log_err(errno, "socket() failed");
    return -1;
  }

  /* TODO: FreeBSD
  if (setsockopt((*redir)->fd, SOL_SOCKET, SO_REUSEPORT,
		 &optval, sizeof(optval))) {
    log_err(errno, "setsockopt() failed");
    close((*redir)->fd);
    return -1;
  }
  */

  /* Set up address */
  address.sin_family = AF_INET;
#if defined(__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)
  address.sin_len = sizeof (struct sockaddr_in);
#endif

  for (n = 0; n < 2 && (*redir)->fd[n]; n++) {

    switch(n) {
    case 0:
      address.sin_addr.s_addr = addr->s_addr;
      address.sin_port = htons(port);
      break;
    case 1:
      /* XXX: binding to 0.0.0.0:uiport (should be configurable?) */
      address.sin_addr.s_addr = INADDR_ANY;
      address.sin_port = htons(uiport);
      break;
    }

    if (setsockopt((*redir)->fd[n], SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
      log_err(errno, "setsockopt() failed");
      close((*redir)->fd[n]);
      (*redir)->fd[n]=0;
      break;
    }
    while (bind((*redir)->fd[n], (struct sockaddr *)&address, sizeof(address))) {
      if ((EADDRINUSE == errno) && (10 > n++)) {
	log_warn(0, "UAM port already in use. Waiting for retry.");
	if (sleep(30)) { /* In case we got killed */
	  close((*redir)->fd[n]);
	  (*redir)->fd[n]=0;
	  break;
	}
      }
      else {
	log_err(errno, "bind() failed");
	close((*redir)->fd[n]);
	(*redir)->fd[n]=0;
	break;
      }
    }
    if (listen((*redir)->fd[n], REDIR_MAXLISTEN)) {
      log_err(errno, "listen() failed");
      close((*redir)->fd[n]);
      (*redir)->fd[n]=0;
      break;
    }
  }
  
  if (((*redir)->msgid = msgget(IPC_PRIVATE, 0)) < 0) {
    log_err(errno, "msgget() failed");
    log_err(0, "Most likely your computer does not have System V IPC installed");
    return -1;
  }
  
  return 0;
}


/* Free instance of redir */
int redir_free(struct redir_t *redir) {
  int n;
  for (n = 0; n < 2 && redir->fd[n]; n++) {
    if (close(redir->fd[n])) {
      log_err(errno, "close() failed");
    }
  }

  if (msgctl(redir->msgid, IPC_RMID, NULL)) {
    log_err(errno, "msgctl() failed");
  }
  
  free(redir);
  return 0;
}

/* Set redir parameters */
void redir_set(struct redir_t *redir, int debug) { 
  optionsdebug = debug; /* TODO: Do not change static variable from instance */
  redir->debug = debug;
  redir->no_uamsuccess = options.no_uamsuccess;
  redir->no_uamwispr = options.no_uamwispr;
  redir->chillixml = options.chillixml;
  redir->url = options.uamurl;
  redir->homepage = options.uamhomepage;
  redir->secret = options.uamsecret;
  redir->ssid = options.ssid;
  redir->nasmac = options.nasmac;
  redir->nasip = options.nasip;
  redir->radiusserver0 = options.radiusserver1;
  redir->radiusserver1 = options.radiusserver2;
  redir->radiusauthport = options.radiusauthport;
  redir->radiusacctport = options.radiusacctport;
  redir->radiussecret  = options.radiussecret;
  redir->radiusnasid  = options.radiusnasid;
  redir->radiuslocationid  = options.radiuslocationid;
  redir->radiuslocationname  = options.radiuslocationname;
  redir->radiusnasporttype = options.radiusnasporttype;
  return;
}

/* Get a parameter of an HTTP request. Parameter is url decoded */
/* TODO: Should be merged with other parsers */
static int redir_getparam(struct redir_t *redir, char *src, char *param,
			  char *dst, int dstsize) {
  char *p1;
  char *p2;
  char sstr[255];
  int len = 0;

  strncpy(sstr, param, sizeof(sstr));
  sstr[sizeof(sstr)-1] = 0;
  strncat(sstr, "=", sizeof(sstr));
  sstr[sizeof(sstr)-1] = 0;

  if (!(p1 = strcasestr(src, sstr))) return -1;
  p1 += strlen(sstr);

  /* The parameter ends with a & or null */
  p2 = strstr(p1, "&");

  if (p2) len = p2 - p1;
  else len = strlen(p1);

  (void)redir_urldecode(p1, len, dst, dstsize);

  log_dbg("The parameter %s is: [%s]", param, dst);/**/

  return 0;

}

/* Read the an HTTP request from a client */
/* If POST is allowed, 1 is the input value of ispost */
static int redir_getreq(struct redir_t *redir, struct redir_socket *sock,
			struct redir_conn_t *conn, int *ispost, int *clen,
			char *qs, int qslen) {
  int fd = sock->fd[0];
  fd_set fds;
  struct timeval idleTime;
  int status;
  int recvlen = 0;
  int buflen = 0;
  char buffer[REDIR_MAXBUFFER];
  char resp[REDIR_URL_LEN];
  char host[256];
  char path[256];
  int i, lines=0, done=0;
  char *eol;

  memset(buffer, 0, sizeof(buffer));
  memset(path, 0, sizeof(path));
  
  /* read whatever the client send to us */
  while (!done && (redir->starttime + REDIR_HTTP_MAX_TIME) > time(NULL)) {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    idleTime.tv_sec = 0;
    idleTime.tv_usec = REDIR_HTTP_SELECT_TIME;

    switch (status = select(fd + 1, &fds, NULL, NULL, &idleTime)) {
    case -1:
      log_err(errno,"select() returned -1!");
      return -1;
    case 0:
      break; 
    default:
      break;
    }

    if ((status > 0) && FD_ISSET(fd, &fds)) {
      if (buflen + 2 >= sizeof(buffer)) { /* ensure space for a least one more byte + null */
        log_err(errno, "too much data in http request!");
        return -1;
      }
      /* if post is allowed, we do not buffer on the read (to not eat post data) */
      if ((recvlen = recv(fd, buffer+buflen, (*ispost) ? 1 : sizeof(buffer)-1-buflen, 0)) < 0) {
	if (errno != ECONNRESET)
	  log_err(errno, "recv() failed!");
	return -1;
      }
      /* TODO: Hack to make Flash work */
      for (i = 0; i < recvlen; i++) if (buffer[buflen+i] == 0) buffer[buflen+i] = 0x0a; 
      buflen += recvlen;
      buffer[buflen] = 0;
    }

    if (buflen <= 0) {
      if (optionsdebug) log_dbg("No HTTP request received!\n");
      return -1;
    }

    while ((eol = strstr(buffer, "\r\n"))) {
      int linelen = eol - buffer;
      *eol = 0;

      if (lines++ == 0) { /* first line */
	char *p1 = buffer;
	char *p2, *p3;
	char *peol;
	int dstlen = 0;

	log_dbg("http-request: %s",buffer);

	if      (!strncmp("GET ",  p1, 4)) { p1 += 4; *ispost = 0; }
	else if (!strncmp("HEAD ", p1, 5)) { p1 += 5; *ispost = 0; }
	else if ((*ispost) && 
		 !strncmp("POST ", p1, 5)) { p1 += 5; *ispost = 1; }
	else return -1;

	while (*p1 == ' ') p1++; /* Advance through additional white space */
	if (*p1 == '/') p1++;
	else return -1;
	
	/* The path ends with a ? or a space */
	p2 = strchr(p1, '?');
	if (!p2) p2 = strchr(p1, ' ');
	if (!p2) return -1;
	dstlen = p2 - p1;

	if (dstlen >= sizeof(path)-1) 
	  dstlen = sizeof(path)-1;

	strncpy(path, p1, dstlen);
	log_dbg("The path: %s", path); 

	/* TODO: Should also check the Host: to make sure we are talking directly to uamlisten */

	if ((!strcmp(path, "logon")) || (!strcmp(path, "login")))
	  conn->type = REDIR_LOGIN;
	else if ((!strcmp(path, "logoff")) || (!strcmp(path, "logout")))
	  conn->type = REDIR_LOGOUT;
	else if (!strncmp(path, "www/", 4) && strlen(path) > 4)
	  conn->type = REDIR_WWW;
	else if (!strncmp(path, "msdownload", 10))
	  { conn->type = REDIR_MSDOWNLOAD; return 0; }
	else if (!strcmp(path, "prelogin"))
	  { conn->type = REDIR_PRELOGIN; return 0; }
	else if (!strcmp(path, "abort"))
	  { conn->type = REDIR_ABORT; return 0; }
	else if (!strcmp(path, "status"))
	  { conn->type = REDIR_STATUS; return 0; }

	if (*p2 == '?') {
	  p1 = p2 + 1;
	  p2 = strchr(p1, ' ');
	  if (p2) {
	    dstlen = p2 - p1;
	    if (dstlen >= qslen-1) 
	      dstlen = qslen-1;
	    strncpy(qs, p1, dstlen);
	    log_dbg("Query string: %s", qs); 
	  }
	}
      } else if (linelen == 0) { 
	/* end of headers */
	log_dbg("end of http-request");
	done = 1;
	break;
      } else { 
	/* headers */
	char *p;
	int len;

	if (!strncasecmp(buffer,"Host:",5)) {
	  p = buffer + 5;
	  while (*p && isspace(*p)) p++;
	  len = strlen(p);
	  if (len >= sizeof(host)-1)
	    len = sizeof(host)-1;
	  strncpy(host, p, len);
	  host[len]=0;
	  log_dbg("Host: %s",host);
	} 
	else if (!strncasecmp(buffer,"Content-Length:",15)) {
	  p = buffer + 15;
	  while (*p && isspace(*p)) p++;
	  len = strlen(p);
	  if (len > 0) *clen = atoi(p);
	  log_dbg("Content-Length: %s",p);
	}
	else if (!strncasecmp(buffer,"User-Agent:",11)) {
	  p = buffer + 11;
	  while (*p && isspace(*p)) p++;
	  len = strlen(p);
	  if (len >= sizeof(conn->useragent)-1)
	    len = sizeof(conn->useragent)-1;
	  strncpy(conn->useragent, p, len);
	  conn->useragent[len]=0;
	  log_dbg("User-Agent: %s",conn->useragent);
	}
      }

      /* shift buffer */
      linelen += 2;
      for (i=0; i < buflen - linelen; i++)
	buffer[i] = buffer[linelen+i];
      buflen -= linelen;
    }
  }

  switch(conn->type) {
  case REDIR_LOGIN:
    {
      /* We look for ident and lang parameters on url and put them on the struct */
      if (!redir_getparam(redir, qs, "lang", conn->lang, sizeof(conn->lang)))
	if (optionsdebug) log_dbg("No lang parameter on url");
      
      if (redir_getparam(redir, qs, "ident", conn->ident, sizeof(conn->ident)))
	strcpy(conn->ident, "0"); /* default value ident = 0 */
      
      if (redir_getparam(redir, qs, "username", 
			 conn->username, sizeof(conn->username))) {
	if (optionsdebug) log_dbg("No username found!");
	return -1;
      }
      
      if (!redir_getparam(redir, qs, "userurl", resp, sizeof(resp))) {
	(void)redir_urldecode(resp, strlen(resp), conn->userurl, sizeof(conn->userurl));
	if (optionsdebug) log_dbg("-->> Setting userurl=[%s]",conn->userurl);
      }
      
      if (redir->secret &&
	  !redir_getparam(redir, qs, "response", resp, sizeof(resp))) {
	(void)redir_hextochar(resp, conn->chappassword);
	conn->chap = 1;
	conn->password[0] = 0;
      }
      else if ((!redir->secret || options.pap_always_ok) && 
	       !redir_getparam(redir, qs, "password", resp, sizeof(resp))) {
	(void)redir_hextochar(resp, conn->password);
	conn->chap = 0;
	conn->chappassword[0] = 0;
      } else {
	if (optionsdebug) log_dbg("No password found!");
	return -1;
      }
    }
    break;

  case REDIR_LOGOUT:
  case REDIR_PRELOGIN:
    {
      if (!redir_getparam(redir, qs, "userurl", resp, sizeof(resp))) {
	(void)redir_urldecode(resp, strlen(resp), conn->userurl, sizeof(conn->userurl));
	if (optionsdebug) log_dbg("-->> Setting userurl=[%s]",conn->userurl);
      }
    } 
    break;

  case REDIR_WWW:
    {
      strncpy(resp, path + 4, sizeof(resp)-1);
      (void)redir_urldecode(resp, strlen(resp), conn->userurl, sizeof(conn->userurl));
      if (optionsdebug) log_dbg("Serving file %s", conn->userurl);
    } 
    break;

  default:
    {
      snprintf(conn->userurl, sizeof(conn->userurl), "http://%s/%s%s%s", 
	       host, path, qs[0] ? "?" : "", qs[0] ? qs : "");
      if (optionsdebug) log_dbg("-->> Setting userurl=[%s]",conn->userurl);
    }
    break;

  }

  return 0;
}

/* Radius callback when access accept/reject/challenge has been received */
static int redir_cb_radius_auth_conf(struct radius_t *radius,
			      struct radius_packet_t *pack,
			      struct radius_packet_t *pack_req, void *cbp) {
  
  struct radius_attr_t *interimattr = NULL;
  struct radius_attr_t *stateattr = NULL;
  struct radius_attr_t *classattr = NULL;
  struct radius_attr_t *attr = NULL;
  char attrs[RADIUS_ATTR_VLEN+1];
  struct tm stt;
  int tzhour, tzmin;
  char *tz;
  int result;
  struct redir_conn_t *conn = (struct redir_conn_t*) cbp;

  if (optionsdebug)
    log_dbg("Received access request confirmation from radius server\n");
  
  if (!conn) {
    log_err(0, "No peer protocol defined");
    conn->response = REDIR_FAILED_OTHER;
    return 0;
  }
  
  if (!pack) { /* Timeout */
    log_err(0, "Radius request timed out");
    conn->response = REDIR_FAILED_OTHER;
    return 0;
  }

  /* We expect ACCESS-ACCEPT, ACCESS-REJECT (or ACCESS-CHALLENGE) */
  if ((pack->code != RADIUS_CODE_ACCESS_REJECT) && 
      (pack->code != RADIUS_CODE_ACCESS_CHALLENGE) &&
      (pack->code != RADIUS_CODE_ACCESS_ACCEPT)) {
    log_err(0, "Unknown radius access reply code %d", pack->code);
    return 0;
  }

  /* Reply message (might be present in both ACCESS-ACCEPT and ACCESS-REJECT */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_REPLY_MESSAGE, 0, 0, 0)) {
    memcpy(conn->replybuf, attr->v.t, attr->l-2);
    conn->replybuf[attr->l-2] = 0;
    conn->reply = conn->replybuf;
  }
  else {
    conn->replybuf[0] = 0;
    conn->reply = NULL;
  }
  
  /* ACCESS-ACCEPT */
  if (pack->code != RADIUS_CODE_ACCESS_ACCEPT) {
    conn->response = REDIR_FAILED_REJECT;
    return 0;
  }

  /* State */
  if (!radius_getattr(pack, &stateattr, RADIUS_ATTR_STATE, 0, 0, 0)) {
    conn->statelen = stateattr->l-2;
    memcpy(conn->statebuf, stateattr->v.t, stateattr->l-2);
  }
  else {
    conn->statelen = 0;
  }
  
  /* Class */
  if (!radius_getattr(pack, &classattr, RADIUS_ATTR_CLASS, 0, 0, 0)) {
    conn->classlen = classattr->l-2;
    memcpy(conn->classbuf, classattr->v.t, classattr->l-2);
  }
  else {
    conn->classlen = 0;
  }

  config_radius_session(&conn->params, pack, 0);

  /* Redirection URL */
  if (!radius_getattr(pack, &attr, RADIUS_ATTR_VENDOR_SPECIFIC,
		      RADIUS_VENDOR_WISPR,
		      RADIUS_ATTR_WISPR_REDIRECTION_URL, 0)) {
    conn->redirurllen = attr->l-2;
    memcpy(conn->redirurlbuf, attr->v.t, attr->l-2);
    conn->redirurlbuf[attr->l-2] = 0;
    conn->redirurl = conn->redirurlbuf;
  }
  else {
    conn->redirurllen = 0;
    conn->redirurlbuf[0] = 0;
    conn->redirurl = NULL;
  }

  if (conn->params.sessionterminatetime) {
    struct timeval timenow;
    gettimeofday(&timenow, NULL);
    if (timenow.tv_sec > conn->params.sessionterminatetime) {
      conn->response = REDIR_FAILED_OTHER;
      log_warn(0, "WISPr-Session-Terminate-Time in the past received: %s", attrs);
    }
  }
  
  conn->response = REDIR_SUCCESS;
  return 0;
  
}

/* Send radius Access-Request and wait for answer */
static int redir_radius(struct redir_t *redir, struct in_addr *addr,
		 struct redir_conn_t *conn) {
  unsigned char chap_password[REDIR_MD5LEN + 1];
  unsigned char chap_challenge[REDIR_MD5LEN];
  unsigned char user_password[REDIR_MD5LEN+1];
  struct radius_packet_t radius_pack;
  struct radius_t *radius;      /* Radius client instance */
  struct timeval idleTime;	/* How long to select() */
  int endtime, now;             /* for radius wait */
  int maxfd = 0;	        /* For select() */
  fd_set fds;			/* For select() */
  int status;

  MD5_CTX context;

  char mac[REDIR_MACSTRLEN+1];
  char url[REDIR_URL_LEN];
  int n;

  if (radius_new(&radius,
		 &redir->radiuslisten, 0, 0,
		 NULL, 0, NULL, NULL, NULL)) {
    log_err(0, "Failed to create radius");
    return -1;
  }

  if (radius->fd > maxfd)
    maxfd = radius->fd;

  radius_set(radius, optionsdebug);
  
  radius_set_cb_auth_conf(radius, redir_cb_radius_auth_conf);

  radius_default_pack(radius, &radius_pack, RADIUS_CODE_ACCESS_REQUEST);
  
  if (optionsdebug) log_dbg("created radius packet (code=%d, id=%d, len=%d)\n",
			   radius_pack.code, radius_pack.id, ntohs(radius_pack.length));
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_NAME, 0, 0, 0,
		 (uint8_t*) conn->username, strlen(conn->username));

  /* If lang on logon url, then send it with attribute ChilliSpot-Lang */
  if(conn->lang[0]) 
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC, 
		   RADIUS_VENDOR_CHILLISPOT, RADIUS_ATTR_CHILLISPOT_LANG, 
		   0, conn->lang, strlen(conn->lang));

  if (redir->secret) {
    /* Get MD5 hash on challenge and uamsecret */
    MD5Init(&context);
    MD5Update(&context, conn->uamchal, REDIR_MD5LEN);
    MD5Update(&context, (uint8_t*) redir->secret, strlen(redir->secret));
    MD5Final(chap_challenge, &context);
  }
  else {
    memcpy(chap_challenge, conn->uamchal, REDIR_MD5LEN);
  }
  
  if (conn->chap == 0) {
    for (n=0; n<REDIR_MD5LEN; n++) 
      user_password[n] = conn->password[n] ^ chap_challenge[n];
    user_password[REDIR_MD5LEN] = 0;
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_USER_PASSWORD, 0, 0, 0,
		   user_password, strlen((char*)user_password));
  }
  else if (conn->chap == 1) {
    chap_password[0] = atoi(conn->ident); /* Chap ident found on logon url */
    memcpy(chap_password +1, conn->chappassword, REDIR_MD5LEN);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CHAP_CHALLENGE, 0, 0, 0,
		   chap_challenge, REDIR_MD5LEN);
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_CHAP_PASSWORD, 0, 0, 0,
		   chap_password, REDIR_MD5LEN+1);
  }

  radius_addnasip(radius, &radius_pack);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_SERVICE_TYPE, 0, 0,
		 RADIUS_SERVICE_TYPE_LOGIN, NULL, 0); /* WISPr_V1.0 */

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_FRAMED_IP_ADDRESS, 0, 0,
		 ntohl(conn->hisip.s_addr), NULL, 0); /* WISPr_V1.0 */

  /* Include his MAC address */
  snprintf(mac, REDIR_MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	   conn->hismac[0], conn->hismac[1],
	   conn->hismac[2], conn->hismac[3],
	   conn->hismac[4], conn->hismac[5]);
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLING_STATION_ID, 0, 0, 0,
		 (uint8_t*) mac, REDIR_MACSTRLEN);
  
  /* Include our MAC address */
  snprintf(mac, REDIR_MACSTRLEN+1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
	   conn->ourmac[0], conn->ourmac[1],
	   conn->ourmac[2], conn->ourmac[3],
	   conn->ourmac[4], conn->ourmac[5]);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_CALLED_STATION_ID, 0, 0, 0,
		 (uint8_t*) mac, REDIR_MACSTRLEN); /* WISPr_V1.0 */

  if (redir->radiusnasid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_IDENTIFIER, 0, 0, 0,
		   (uint8_t*) redir->radiusnasid, 
		   strlen(redir->radiusnasid)); /* WISPr_V1.0 */


  radius_addattr(radius, &radius_pack, RADIUS_ATTR_ACCT_SESSION_ID, 0, 0, 0,
		 (uint8_t*) conn->sessionid, REDIR_SESSIONID_LEN-1);


  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT_TYPE, 0, 0,
		 redir->radiusnasporttype, NULL, 0);

  radius_addattr(radius, &radius_pack, RADIUS_ATTR_NAS_PORT, 0, 0,
		 conn->nasport, NULL, 0);
  
  if (redir->radiuslocationid)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_ID, 0,
		   (uint8_t*) redir->radiuslocationid,
		   strlen(redir->radiuslocationid));

  if (redir->radiuslocationname)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOCATION_NAME, 0,
		   (uint8_t*) redir->radiuslocationname, 
		   strlen(redir->radiuslocationname));

  if (snprintf(url, sizeof(url)-1, "http://%s:%d/logoff", 
	       inet_ntoa(redir->addr), redir->port) > 0)
    radius_addattr(radius, &radius_pack, RADIUS_ATTR_VENDOR_SPECIFIC,
		   RADIUS_VENDOR_WISPR, RADIUS_ATTR_WISPR_LOGOFF_URL, 0,
		   url, strlen(url));
  
  radius_addattr(radius, &radius_pack, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, 
		 0, 0, 0, NULL, RADIUS_MD5LEN);

  if (optionsdebug) log_dbg("sending radius packet (code=%d, id=%d, len=%d)\n",
			   radius_pack.code, radius_pack.id, ntohs(radius_pack.length));

  radius_req(radius, &radius_pack, conn);

  now = time(NULL);
  endtime = now + REDIR_RADIUS_MAX_TIME;

  while (endtime > now) {

    FD_ZERO(&fds);
    if (radius->fd != -1) FD_SET(radius->fd, &fds);
    if (radius->proxyfd != -1) FD_SET(radius->proxyfd, &fds);
    
    idleTime.tv_sec = 0;
    idleTime.tv_usec = REDIR_RADIUS_SELECT_TIME;
    radius_timeleft(radius, &idleTime);

    switch (status = select(maxfd + 1, &fds, NULL, NULL, &idleTime)) {
    case -1:
      log_err(errno, "select() returned -1!");
      break;  
    case 0:
      if (optionsdebug) log_dbg("Select returned 0\n");
      radius_timeout(radius);
      break; 
    default:
      break;
    }

    if (status > 0) {
      if ((radius->fd != -1) && FD_ISSET(radius->fd, &fds) && 
	  radius_decaps(radius) < 0) {
	log_err(0, "radius_ind() failed!");
      }
      
      if ((radius->proxyfd != -1) && FD_ISSET(radius->proxyfd, &fds) && 
	  radius_proxy_ind(radius) < 0) {
	log_err(0, "radius_proxy_ind() failed!");
      }
    }
  
    if (conn->response) {
      radius_free(radius);
      return 0;
    }
    now = time(NULL);
  }

  return 0;
}

int set_nonblocking(int fd)
{
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) return -1;
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  return 0;
}

int clear_nonblocking(int fd)
{
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) return -1;
  fcntl(fd, F_SETFL, flags & (~O_NONBLOCK));
  return 0;
}

int is_local_user(struct redir_t *redir, struct redir_conn_t *conn) {
  unsigned char user_password[REDIR_MD5LEN+1];
  unsigned char chap_challenge[REDIR_MD5LEN];
  unsigned char tmp[REDIR_MD5LEN+1];
  char u[256]; char p[256];
  size_t sz=1024;
  int len, match=0;
  char *line=0;
  MD5_CTX context;
  FILE *f;

  if (!options.localusers) return 0;

  log_dbg("checking %s for user %s", options.localusers, conn->username);

  if (!(f = fopen(options.localusers, "r"))) {
    log_err(errno, "fopen() failed opening %s!", options.localusers);
    return 0;
  }

  if (options.debug) {/*debug*/
    char buffer[64];
    redir_chartohex(conn->uamchal, buffer);
    log_dbg("challenge: %s", buffer);
  }/**/

  if (redir->secret) {
    MD5Init(&context);
    MD5Update(&context, conn->uamchal, REDIR_MD5LEN);
    MD5Update(&context, redir->secret, strlen(redir->secret));
    MD5Final(chap_challenge, &context);
  }
  else {
    memcpy(chap_challenge, conn->uamchal, REDIR_MD5LEN);
  }

  if (options.debug) {/*debug*/
    char buffer[64];
    redir_chartohex(chap_challenge, buffer);
    log_dbg("chap challenge: %s", buffer);
  }/**/

  if (conn->chap == 0) {
    int n;
    for (n=0; n < REDIR_MD5LEN; n++)
      user_password[n] = conn->password[n] ^ chap_challenge[n];
  }
  else if (conn->chap == 1) {
    memcpy(user_password, conn->chappassword, REDIR_MD5LEN);
  }
  
  user_password[REDIR_MD5LEN] = 0;
	
  log_dbg("looking for %s", conn->username);

  line=(char*)malloc(sz);
  while ((len = getline(&line, &sz, f)) >= 0) {
    if (len > 3 && len < sizeof(u) && line[0] != '#') {
      char *pl=line, *pu=u, *pp=p;
      while (*pl && *pl != ':') *pu++ = *pl++;
      if (*pl == ':') *pl++;
      while (*pl && *pl != ':' && *pl != '\n') *pp++ = *pl++;
      *pu = 0; *pp = 0;

      if (!strcmp(conn->username, u)) {

	log_dbg("found %s, checking password", u);

	if (conn->chap == 0) {
	  int n;
	  for (n=0; n < REDIR_MD5LEN; n++)
	    tmp[n] = p[n] ^ chap_challenge[n];
	}
	else if (conn->chap == 1) {
	  MD5Init(&context);
	  MD5Update(&context, "\0", 1);	  
	  MD5Update(&context, p, strlen(p));
	  MD5Update(&context, chap_challenge, REDIR_MD5LEN);
	  MD5Final(tmp, &context);
	}

	tmp[REDIR_MD5LEN] = 0;

	if (!memcmp(user_password, tmp, REDIR_MD5LEN)) 
	  match = 1; 

	break;
      }
    }
  }
  
  log_dbg("user %s %s", conn->username, match ? "found" : "not found");

  fclose(f);
  free(line);
  return match;
}


/* redir_accept() does the following:
 1) forks a child process
 2) Accepts the tcp connection 
 3) Analyses a HTTP get request
 4) GET request can be one of the following:
    a) Logon request with username and challenge response
       - Does a radius request
       - If OK send result to parent and redirect to welcome page
       - Else redirect to error login page
    b) Logoff request
       - Send logoff request to parent
       - Redirect to login page?
    c) Request for another server
       - Redirect to login server.

 Incoming requests are identified only by their IP address. No MAC
 address information is obtained. The main security problem is denial
 of service attacks by malicious hosts sending logoff requests for
 clients. This can be prevented by checking incoming packets for
 matching MAC and src IP addresses.
*/

int redir_accept(struct redir_t *redir, int idx) {
  int status;
  int new_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);


  if ((new_socket = accept(redir->fd[idx], (struct sockaddr *)&address, (socklen_t*) &addrlen)) < 0) {
    if (errno != ECONNABORTED)
      log_err(errno, "accept() failed!");
    return 0;
  }


  /* This forks a new process. The child really should close all
     unused file descriptors and free memory allocated. This however
     is performed when the process exits, so currently we don't
     care */
  
  if ((status = fork()) < 0) {
    log_err(errno, "fork() returned -1!");
    return 0;
  }

  if (status > 0) { /* Parent */
    close(new_socket);
    return 0; 
  }

#if defined(F_DUPFD)
  if (fcntl(new_socket,F_GETFL,0) == -1) return -1;
  close(0);
  if (fcntl(new_socket,F_DUPFD,0) == -1) return -1;
  if (fcntl(new_socket,F_GETFL,1) == -1) return -1;
  close(1);
  if (fcntl(new_socket,F_DUPFD,1) == -1) return -1;
#else
  if (dup2(new_socket,0) == -1) return -1;
  if (dup2(new_socket,1) == -1) return -1;
#endif
    
  if (idx == 1 && options.uamui) {
    char *binqqargs[2] = { options.uamui, 0 } ;
    char buffer[56];

    snprintf(buffer,sizeof(buffer)-1,"%s",inet_ntoa(address.sin_addr));
    setenv("TCPREMOTEIP",buffer,1);
    setenv("REMOTE_ADDR",buffer,1);
    snprintf(buffer,sizeof(buffer)-1,"%d",ntohs(address.sin_port));
    setenv("TCPREMOTEPORT",buffer,1);
    setenv("REMOTE_PORT",buffer,1);

    execv(*binqqargs, binqqargs);

  } else return redir_main(redir, 0, 1, &address, idx);
}

int redir_main(struct redir_t *redir, int infd, int outfd, struct sockaddr_in *address, int isui) {
  char hexchal[1+(2*REDIR_MD5LEN)];
  unsigned char challenge[REDIR_MD5LEN];
  int bufsize = REDIR_MAXBUFFER;
  char buffer[bufsize+1];
  char qs[REDIR_USERURLSIZE];
  struct redir_msg_t msg;
  int buflen;
  int state = 0;

  struct redir_conn_t conn;
  struct sigaction act, oldact;
  struct itimerval itval;
  struct redir_socket socket;
  int ispost = isui;
  int clen = 0;

  /* Close of socket */
  void redir_close () {
    if (shutdown(outfd, SHUT_WR) != 0)
      log_err(errno, "shutdown socket for writing");

    if (!set_nonblocking(infd)) 
      while(read(infd, buffer, sizeof(buffer)) > 0);

    if (shutdown(infd, SHUT_RD) != 0)
      log_err(errno, "shutdown socket for reading");

    close(outfd);
    close(infd);
    exit(0);
  }
  
  void redir_memcopy(int msg_type) {
    redir_challenge(challenge);
    (void)redir_chartohex(challenge, hexchal);
    msg.type = msg_type;
    msg.addr = address->sin_addr;
    memcpy(msg.uamchal, challenge, REDIR_MD5LEN);
    if (options.debug) {
      log_dbg("---->>> resetting challenge: %s", hexchal);
    }
  }

  memset(&socket,0,sizeof(socket));

  socket.fd[0] = infd;
  socket.fd[1] = outfd;

  redir->starttime = time(NULL);

  if (set_nonblocking(socket.fd[0])) {
    log_err(errno, "fcntl() failed");
    redir_close();
  }

  memset(hexchal, 0, sizeof(hexchal));
  memset(qs, 0, sizeof(qs));
  memset(&conn, 0, sizeof(conn));
  memset(&msg, 0, sizeof(msg));
  memset(&act, 0, sizeof(act));

  act.sa_handler = redir_termination;
  sigaction(SIGTERM, &act, &oldact);
  sigaction(SIGINT, &act, &oldact);
  act.sa_handler = redir_alarm;
  sigaction(SIGALRM, &act, &oldact);

  memset(&itval, 0, sizeof(itval));
  itval.it_interval.tv_sec = REDIR_MAXTIME; 
  itval.it_interval.tv_usec = 0; 
  itval.it_value.tv_sec = REDIR_MAXTIME;
  itval.it_value.tv_usec = 0; 

  if (setitimer(ITIMER_REAL, &itval, NULL)) {
    log_err(errno, "setitimer() failed!");
  }

  termstate = REDIR_TERM_GETREQ;
  if (optionsdebug) log_dbg("Calling redir_getreq()\n");

  if (redir_getreq(redir, &socket, &conn, &ispost, &clen, qs, sizeof(qs))) {
    if (optionsdebug) log_dbg("Error calling get_req. Terminating\n");
    redir_close();
  }

  if (conn.type == REDIR_WWW) {
    int fd = -1;
    if (options.wwwdir && conn.userurl && *conn.userurl) {
      char *ctype = "text/plain";
      char *filename = conn.userurl;
      int namelen = strlen(filename);
      int parse = 0;
      
      /* check filename */
      { char *p;
	for (p=filename; *p; p++) {
	  if (*p >= 'a' && *p <= 'z') 
	    continue;
	  switch(*p) {
	  case '.':
	  case '_':
	  case '-':
	    break;
	  default:
	    /* invalid file name! */
	    log_err(0, "invalid www request [%s]!", filename);
	    redir_close();
	  }
	}
      }
      
      /* serve the local content */
      
      if      (!strcmp(filename + (namelen - 5), ".html")) ctype = "text/html";
      else if (!strcmp(filename + (namelen - 4), ".gif"))  ctype = "image/gif";
      else if (!strcmp(filename + (namelen - 4), ".jpg"))  ctype = "image/jpeg";
      else if (!strcmp(filename + (namelen - 4), ".png"))  ctype = "image/png";
      else if (!strcmp(filename + (namelen - 4), ".swf"))  ctype = "application/x-shockwave-flash";
      else if (!strcmp(filename + (namelen - 4), ".chi")){ ctype = "text/html"; parse = 1; }
      else { 
	/* we do not serve it! */
	log_err(0, "invalid file extension! [%s]", filename);
	redir_close();
      }
      
      if (parse) {
	FILE *f;
	
	if (!options.wwwbin) {
	  log_err(0, "the 'wwwbin' setting must be configured for CGI use");
	  redir_close();
	}
	
	if (clear_nonblocking(socket.fd[0])) {
	  log_err(errno, "fcntl() failed");
	}
	
	/* XXX: Todo: look for malicious content! */
	
	sprintf(buffer,"%d", clen > 0 ? clen : 0);
	setenv("CONTENT_LENGTH", buffer, 1);
	setenv("REQUEST_METHOD", ispost ? "POST" : "GET", 1);
	setenv("QUERY_STRING", qs, 1);
	
	log_dbg("Running: %s %s/%s",options.wwwbin, options.wwwdir, filename);
	sprintf(buffer, "%s/%s", options.wwwdir, filename);
	
	{
	  char *binqqargs[3] = { options.wwwbin, buffer, 0 } ;
	  int status;
	  
	  if ((status = fork()) < 0) {
	    log_err(errno, "fork() returned -1!");
	    /* lets just execv and ignore the extra crlf problem */
	    execv(*binqqargs, binqqargs);
	  }
	  
	  if (status > 0) { /* Parent */
	    /* now wait for the child (the cgi-prog) to finish
	     * and let redir_close remove unwanted data
	     * (for instance) extra crlf from ie7 in POSTs)
	     * to avoid a tcp-reset.
	     */
	    wait(NULL);
	  }
	  else {
	    /* Child */
	    execv(*binqqargs, binqqargs);
	  }
	}
	
	redir_close();
      }
      
      if (!chroot(options.wwwdir) && !chdir("/")) {
	
	fd = open(filename, O_RDONLY);
	
	if (fd > 0) {
	  
	  if (clear_nonblocking(socket.fd[0])) {
	    log_err(errno, "fcntl() failed");
	  }
	  
	  buflen = snprintf(buffer, bufsize,
			    "HTTP/1.0 200 OK\r\nContent-type: %s\r\n\r\n", ctype);
	  
	  if (tcp_write(&socket, buffer, buflen) < 0) {
	    log_err(errno, "tcp_write() failed!");
	  }
	  
	  while ((buflen = read(fd, buffer, bufsize)) > 0)
	    if (tcp_write(&socket, buffer, buflen) < 0)
	      log_err(errno, "tcp_write() failed!");
	  
	  close(fd);
	  redir_close(); /* which exits */
	} 
	else log_err(0, "could not open local content file %s!", filename);
      }
      else log_err(0, "chroot to %s was not successful\n", options.wwwdir); 
    } 
    else log_err(0, "Required: 'wwwdir' (in chilli.conf) and 'file' query-string param\n"); 
    
    redir_close();
  }


  termstate = REDIR_TERM_GETSTATE;
  if (optionsdebug) log_dbg("Calling cb_getstate()\n");
  if (!redir->cb_getstate) { log_err(0, "No cb_getstate() defined!"); redir_close(); }

  state = redir->cb_getstate(redir, &address->sin_addr, &conn);

  termstate = REDIR_TERM_PROCESS;
  if (optionsdebug) log_dbg("Processing received request\n");

  switch (conn.type) {

  case REDIR_LOGIN:
    
    /* Was client was already logged on? */
    if (state == 1) {
      log_dbg("redir_accept: already logged on");
      redir_reply(redir, &socket, &conn, REDIR_ALREADY, NULL, 0, 
		  NULL, NULL, conn.userurl, NULL,
		  NULL, conn.hismac, &conn.hisip);
      redir_close();
    }

    /* Did the challenge expire? */
    if ((conn.uamtime + REDIR_CHALLENGETIMEOUT2) < time(NULL)) {
      log_dbg("redir_accept: challenge expired: %d : %d", conn.uamtime, time(NULL));
      redir_memcopy(REDIR_CHALLENGE);      
      if (msgsnd(redir->msgid, (struct msgbuf*) &msg, 
		 sizeof(struct redir_msg_t), 0) < 0) {
	log_err(errno, "msgsnd() failed!");
	redir_close();
      }

      redir_reply(redir, &socket, &conn, REDIR_FAILED_OTHER, NULL, 
		  0, hexchal, NULL, NULL, NULL, 
		  NULL, conn.hismac, &conn.hisip);
      redir_close();
    }

    if (is_local_user(redir, &conn)) { 
       conn.response = REDIR_SUCCESS;
    }
    else {
      termstate = REDIR_TERM_RADIUS;
      if (optionsdebug) log_dbg("redir_accept: Sending radius request\n");
      redir_radius(redir, &address->sin_addr, &conn);
      termstate = REDIR_TERM_REPLY;
      if (optionsdebug) log_dbg("Received radius reply\n");
    }

    if (conn.response == REDIR_SUCCESS) { /* Radius-Accept */
      char *besturl = conn.redirurl;
      if (!(besturl && besturl[0])) besturl = conn.userurl;

      if (redir->no_uamsuccess && besturl && besturl[0])
	redir_reply(redir, &socket, &conn, conn.response, besturl, conn.params.sessiontimeout,
		    hexchal, conn.username, besturl, conn.reply,
		    conn.redirurl, conn.hismac, &conn.hisip);
      else 
	redir_reply(redir, &socket, &conn, conn.response, NULL, conn.params.sessiontimeout,
		    hexchal, conn.username, conn.userurl, conn.reply,
		    conn.redirurl, conn.hismac, &conn.hisip);
      
      msg.type = REDIR_LOGIN;
      strncpy(msg.username, conn.username, sizeof(msg.username));
      msg.username[sizeof(msg.username)-1] = 0;
      msg.statelen = conn.statelen;
      memcpy(msg.statebuf, conn.statebuf, conn.statelen);
      msg.classlen = conn.classlen;
      memcpy(msg.classbuf, conn.classbuf, conn.classlen);
      msg.addr = address->sin_addr;

      memcpy(&msg.params, &conn.params, sizeof(msg.params));

      if (conn.userurl && *conn.userurl) {
	strncpy(msg.userurl, conn.userurl, sizeof(msg.userurl));
	msg.userurl[sizeof(msg.userurl)-1] = 0;
	if (optionsdebug) log_dbg("-->> Msg userurl=[%s]\n",conn.userurl);
      }
      
      if (msgsnd(redir->msgid, (struct msgbuf*) &msg,
		 sizeof(struct redir_msg_t), 0) < 0) {
	log_err(errno, "msgsnd() failed!");
      }
    }
    else {
      redir_memcopy(REDIR_CHALLENGE);      
      if (msgsnd(redir->msgid, (struct msgbuf*) &msg, 
		 sizeof(struct redir_msg_t), 0) < 0) {
	log_err(errno, "msgsnd() failed!");
      } else {
	redir_reply(redir, &socket, &conn, conn.response, NULL, 0, 
		    hexchal, NULL, conn.userurl, conn.reply, 
		    NULL, conn.hismac, &conn.hisip);
      }
    }    
    redir_close();

  case REDIR_LOGOUT:
    {
      char *besturl = conn.redirurl;
      redir_memcopy(REDIR_LOGOUT); 
      if (msgsnd(redir->msgid, (struct msgbuf*) &msg, 
		 sizeof(struct redir_msg_t), 0) < 0) {
	log_err(errno, "msgsnd() failed!");
	redir_close();
      }
      
      if (!(besturl && besturl[0])) besturl = conn.userurl;
      if (redir->no_uamsuccess && besturl && besturl[0])
	redir_reply(redir, &socket, &conn, REDIR_LOGOFF, besturl, 0, 
		    hexchal, NULL, conn.userurl, NULL, 
		    NULL, conn.hismac, &conn.hisip);
      else 
	redir_reply(redir, &socket, &conn, REDIR_LOGOFF, NULL, 0, 
		    hexchal, NULL, conn.userurl, NULL, 
		    NULL, conn.hismac, &conn.hisip);
      
      redir_close();    
    }
    
  case REDIR_PRELOGIN:

    /* Did the challenge expire? */
    if ((conn.uamtime + REDIR_CHALLENGETIMEOUT1) < time(NULL)) {
      redir_memcopy(REDIR_CHALLENGE);
      if (msgsnd(redir->msgid, (struct msgbuf*) &msg,  sizeof(msg), 0) < 0) {
	log_err(errno, "msgsnd() failed!");
	redir_close();
      }
    }
    else {
      (void)redir_chartohex(conn.uamchal, hexchal);
    }
    
    if (state == 1) {
      redir_reply(redir, &socket, &conn, REDIR_ALREADY, 
		  NULL, 0, NULL, NULL, conn.userurl, NULL,
		  NULL, conn.hismac, &conn.hisip);
    }
    else {
      redir_reply(redir, &socket, &conn, REDIR_NOTYET, 
		  NULL, 0, hexchal, NULL, conn.userurl, NULL, 
		  NULL, conn.hismac, &conn.hisip);
    }
    redir_close();

  case REDIR_ABORT:

    if (state == 1) {
      redir_reply(redir, &socket, &conn, REDIR_ABORT_NAK, 
		  NULL, 0, NULL, NULL, conn.userurl, NULL, 
		  NULL, conn.hismac, &conn.hisip);
    }
    else {
      redir_memcopy(REDIR_ABORT);
      if (msgsnd(redir->msgid, (struct msgbuf*) &msg, 
		 sizeof(struct redir_msg_t), 0) < 0) {
	log_err(errno, "msgsnd() failed!");
	redir_close();
      }
      redir_reply(redir, &socket, &conn, REDIR_ABORT_ACK, 
		  NULL, 0, hexchal, NULL, conn.userurl, NULL, 
		  NULL, conn.hismac, &conn.hisip);
    }
    redir_close();

  case REDIR_ABOUT:
    redir_reply(redir, &socket, &conn, REDIR_ABOUT, NULL, 
		0, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    redir_close();

  case REDIR_STATUS:
    {
      uint32_t sessiontime;
      uint32_t timeleft;
      struct timeval timenow;
      gettimeofday(&timenow, NULL);
      sessiontime = timenow.tv_sec - conn.start_time.tv_sec;
      sessiontime += (timenow.tv_usec - conn.start_time.tv_usec) / 1000000;
      if (conn.params.sessiontimeout)
	timeleft = conn.params.sessiontimeout - sessiontime;
      else
	timeleft = 0;
      
      redir_reply(redir, &socket, &conn, REDIR_STATUS, NULL, timeleft,
		  NULL, NULL, NULL, NULL, NULL, NULL, NULL);
      redir_close();
    }

  case REDIR_MSDOWNLOAD:
    buflen = snprintf(buffer, bufsize, "HTTP/1.0 403 Forbidden\r\n\r\n");
    tcp_write(&socket, buffer, buflen);
    redir_close();
  }

  /* It was not a request for a known path. It must be an original request */
  if (optionsdebug) log_dbg("redir_accept: Original request\n");

  /* Did the challenge expire? */
  if ((conn.uamtime + REDIR_CHALLENGETIMEOUT1) < time(NULL)) {
    redir_memcopy(REDIR_CHALLENGE);
    strncpy(msg.userurl, conn.userurl, sizeof(msg.userurl));
    msg.userurl[sizeof(msg.userurl)-1] = 0;
    if (optionsdebug) log_dbg("-->> Msg userurl=[%s]\n",msg.userurl);
    if (msgsnd(redir->msgid, (struct msgbuf*) &msg, 
	       sizeof(struct redir_msg_t), 0) < 0) {
      log_err(errno, "msgsnd() failed!");
      redir_close();
    }
  }
  else {
    (void)redir_chartohex(conn.uamchal, hexchal);
  }
  
  if (redir->homepage) {
    char url[REDIR_URL_LEN+1];
    char urlEnc[REDIR_URL_LEN+1];

    if (redir_buildurl(&conn, url, sizeof(url), redir, "notyet", 0, hexchal, NULL,
		       conn.userurl, NULL, NULL, conn.hismac, &conn.hisip) == -1) {
      log_err(errno, "redir_buildurl failed!");
      redir_close();
    }

    redir_urlencode(url, strlen(url), urlEnc, sizeof(urlEnc));

    snprintf(url, REDIR_URL_LEN, "%s%cloginurl=%s",
	     redir->homepage, strchr(redir->homepage, '?') ? '&' : '?', urlEnc);

    redir_reply(redir, &socket, &conn, REDIR_NOTYET, url, 
		0, hexchal, NULL, conn.userurl, NULL, 
		NULL, conn.hismac, &conn.hisip);
  }
  else if (state == 1) {
    redir_reply(redir, &socket, &conn, REDIR_ALREADY, NULL, 0, 
		NULL, NULL, conn.userurl, NULL,
		NULL, conn.hismac, &conn.hisip);
  }
  else {
    redir_reply(redir, &socket, &conn, REDIR_NOTYET, NULL, 
		0, hexchal, NULL, conn.userurl, NULL, 
		NULL, conn.hismac, &conn.hisip);
  }

  redir_close();
  return -1; /* never gets here */
}


/* Set callback to determine state information for the connection */
int redir_set_cb_getstate(struct redir_t *redir,
  int (*cb_getstate) (struct redir_t *redir, struct in_addr *addr,
		      struct redir_conn_t *conn)) {
  redir->cb_getstate = cb_getstate;
  return 0;
}
