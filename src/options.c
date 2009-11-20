/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2006 PicoPoint B.V.
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
#include "radius_wispr.h"
#include "radius_chillispot.h"
#include "redir.h"
#include "syserr.h"
#include "dhcp.h"
#include "cmdline.h"
#include "chilli.h"
#include "options.h"

void options_init() {
  memset(&_options, 0, sizeof(_options));
}

/* Get IP address and mask */
int option_aton(struct in_addr *addr, struct in_addr *mask,
		char *pool, int number) {

  /* Parse only first instance of network for now */
  /* Eventually "number" will indicate the token which we want to parse */

  unsigned int a1, a2, a3, a4;
  unsigned int m1, m2, m3, m4;
  unsigned int m;
  int masklog;
  int c;

  c = sscanf(pool, "%u.%u.%u.%u/%u.%u.%u.%u",
	     &a1, &a2, &a3, &a4,
	     &m1, &m2, &m3, &m4);

  switch (c) {
  case 4:
    mask->s_addr = 0xffffffff;
    break;
  case 5:
    if (m1 > 32) {
      log_err(0, "Invalid mask");
      return -1; /* Invalid mask */
    }
    mask->s_addr = htonl(0xffffffff << (32 - m1));
    break;
  case 8:
    if (m1 >= 256 ||  m2 >= 256 || m3 >= 256 || m4 >= 256) {
      log_err(0, "Invalid mask");
      return -1; /* Wrong mask format */
    }
    m = m1 * 0x1000000 + m2 * 0x10000 + m3 * 0x100 + m4;
    for (masklog = 0; ((1 << masklog) < ((~m)+1)); masklog++);
    if (((~m)+1) != (1 << masklog)) {
      log_err(0, "Invalid mask");
      return -1; /* Wrong mask format (not all ones followed by all zeros)*/
    }
    mask->s_addr = htonl(m);
    break;
  default:
    log_err(0, "Invalid mask");
    return -1; /* Invalid mask */
  }

  if (a1 >= 256 ||  a2 >= 256 || a3 >= 256 || a4 >= 256) {
    log_err(0, "Wrong IP address format");
    return -1;
  }
  else
    addr->s_addr = htonl(a1 * 0x1000000 + a2 * 0x10000 + a3 * 0x100 + a4);

  return 0;
}

static int option_s_s(bstring str, char **sp) {
  char *s = *sp ? *sp : "";
  size_t len = strlen(s) + 1;
  *sp = (char *)(size_t)str->slen;
  if (bcatblk(str, s, len) != BSTR_OK) return 0;
  return 1;
}

static int option_s_l(bstring str, char **s) {
  size_t offset = (size_t) *s;
  *s = ((char *)str->data) + offset;
  if (!**s) *s = 0;
  return 1;
}

static int opt_run(int argc, char **argv, int reload) {
  char **newargs;
  char file[128];
  int status;
  int i;

  snprintf(file,sizeof(file),"/tmp/chilli-%d/config.bin",getpid());

  if ((status = fork()) < 0) {
    log_err(errno, "fork() returned -1!");
    return -1;
  }
  
  if (status > 0) { /* Parent */
    return status;
  }

  newargs = calloc(1, sizeof(char *) * (argc + 4));

  for (i=1; i < argc; i++) {
    newargs[i] = argv[i];
  }

  newargs[0] = "chilli_opt";
  newargs[i++] = "-b";
  newargs[i++] = file;
  newargs[i++] = reload ? "-r" : NULL;

  if (execv(SBINDIR "/chilli_opt", newargs) != 0) {
    log_err(errno, "execl() did not return 0!");
    exit(0);
  }

  exit(0);
}


int options_load(int argc, char **argv, bstring bt) {
  char file[128];
  int fd;

  snprintf(file,sizeof(file),"/tmp/chilli-%d/config.bin",getpid());
  fd = open(file, O_RDONLY);

  while (fd <= 0) {
    int status = 0;
    int pid = opt_run(argc, argv, 0);
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 2) exit(0);
    fd = open(file, O_RDONLY);
    if (fd <= 0) {
      log_warn(0, "could not generate configuration, sleeping one second");
      sleep(1);
    }
  }

  if (fd <= 0) {
    return 0;
  } else {
    return options_fromfd(fd, bt);
  }
}

int options_fromfd(int fd, bstring bt) {

  struct options_t o;
  char has_error = 1;
  size_t len;
  int i;
  
  int rd = safe_read(fd, &o, sizeof(o));

  if (rd == sizeof(o)) {
    rd = safe_read(fd, &len, sizeof(len));
    if (rd == sizeof(len)) {
      ballocmin(bt, len);
      rd = safe_read(fd, bt->data, len);
      if (rd == len) {
	has_error = 0;
      }
    }
  }
  
  if (has_error) {
    log_err(errno, "could not read configuration");
    close(fd);
    return 0;
  }
  
  close(fd);

  if (!option_s_l(bt, &o.pidfile)) return 0;
  if (!option_s_l(bt, &o.statedir)) return 0;
  if (!option_s_l(bt, &o.usestatusfile)) return 0;
  if (!option_s_l(bt, &o.tundev)) return 0;
  if (!option_s_l(bt, &o.dynip)) return 0;
  if (!option_s_l(bt, &o.statip)) return 0;

  if (!option_s_l(bt, &o.domain)) return 0;
  if (!option_s_l(bt, &o.ipup)) return 0;
  if (!option_s_l(bt, &o.ipdown)) return 0;
  if (!option_s_l(bt, &o.conup)) return 0;
  if (!option_s_l(bt, &o.condown)) return 0;

  if (!option_s_l(bt, &o.radiussecret)) return 0;
  if (!option_s_l(bt, &o.radiusnasid)) return 0;
  if (!option_s_l(bt, &o.radiuslocationid)) return 0;
  if (!option_s_l(bt, &o.radiuslocationname)) return 0;
  if (!option_s_l(bt, &o.locationname)) return 0;
  if (!option_s_l(bt, &o.proxysecret)) return 0;
  
  if (!option_s_l(bt, &o.dhcpif)) return 0;
  if (!option_s_l(bt, &o.routeif)) return 0;

  if (!option_s_l(bt, &o.macsuffix)) return 0;
  if (!option_s_l(bt, &o.macpasswd)) return 0;

  if (!option_s_l(bt, &o.uamsecret)) return 0;
  if (!option_s_l(bt, &o.uamurl)) return 0;
  if (!option_s_l(bt, &o.uamaaaurl)) return 0;
  if (!option_s_l(bt, &o.uamhomepage)) return 0;
  if (!option_s_l(bt, &o.wisprlogin)) return 0;

  if (!option_s_l(bt, &o.wwwdir)) return 0;
  if (!option_s_l(bt, &o.wwwbin)) return 0;
  if (!option_s_l(bt, &o.uamui)) return 0;
  if (!option_s_l(bt, &o.localusers)) return 0;
#ifdef HAVE_OPENSSL
  if (!option_s_l(bt, &o.sslkeyfile)) return 0;
  if (!option_s_l(bt, &o.sslcertfile)) return 0;
#endif
#ifdef USING_IPC_UNIX
  if (!option_s_l(bt, &o.unixipc)) return 0;
#endif

  if (!option_s_l(bt, &o.adminuser)) return 0;
  if (!option_s_l(bt, &o.adminpasswd)) return 0;
  if (!option_s_l(bt, &o.adminupdatefile)) return 0;
  if (!option_s_l(bt, &o.rtmonfile)) return 0;

  if (!option_s_l(bt, &o.ssid)) return 0;
  if (!option_s_l(bt, &o.vlan)) return 0;
  if (!option_s_l(bt, &o.nasmac)) return 0;
  if (!option_s_l(bt, &o.nasip)) return 0;
  if (!option_s_l(bt, &o.cmdsocket)) return 0;

  if (!option_s_l(bt, &o.uamaliasname)) return 0;
  
  for (i=0; i < MAX_UAM_DOMAINS; i++) {
    if (!option_s_l(bt, &o.uamdomains[i])) 
      return 0;
  }

#ifdef ENABLE_CHILLIREDIR
  for (i = 0; i < MAX_REGEX_PASS_THROUGHS; i++) {
    if (_options.regex_pass_throughs[i].re_host.allocated)
      regfree(&_options.regex_pass_throughs[i].re_host);
    if (_options.regex_pass_throughs[i].re_path.allocated)
      regfree(&_options.regex_pass_throughs[i].re_path);
    if (_options.regex_pass_throughs[i].re_qs.allocated)
      regfree(&_options.regex_pass_throughs[i].re_qs);
  }
#endif

  if (_options._data) free(_options._data);
  memcpy(&_options, &o, sizeof(o));
  _options._data = (char *)bt->data;

  return 1;
}

int options_save(char *file, bstring bt) {
  struct options_t o;
  mode_t oldmask;
  int fd, i;

  memcpy(&o, &_options, sizeof(o));

#ifdef ENABLE_CHILLIREDIR
  for (i = 0; i < MAX_REGEX_PASS_THROUGHS; i++) {
    memset(&o.regex_pass_throughs[i].re_host, 0, sizeof(regex_t));
    memset(&o.regex_pass_throughs[i].re_path, 0, sizeof(regex_t));
    memset(&o.regex_pass_throughs[i].re_qs, 0, sizeof(regex_t));
  }
#endif

  if (!option_s_s(bt, &o.pidfile)) return 0;
  if (!option_s_s(bt, &o.statedir)) return 0;
  if (!option_s_s(bt, &o.usestatusfile)) return 0;
  if (!option_s_s(bt, &o.tundev)) return 0;
  if (!option_s_s(bt, &o.dynip)) return 0;
  if (!option_s_s(bt, &o.statip)) return 0;

  if (!option_s_s(bt, &o.domain)) return 0;
  if (!option_s_s(bt, &o.ipup)) return 0;
  if (!option_s_s(bt, &o.ipdown)) return 0;
  if (!option_s_s(bt, &o.conup)) return 0;
  if (!option_s_s(bt, &o.condown)) return 0;

  if (!option_s_s(bt, &o.radiussecret)) return 0;
  if (!option_s_s(bt, &o.radiusnasid)) return 0;
  if (!option_s_s(bt, &o.radiuslocationid)) return 0;
  if (!option_s_s(bt, &o.radiuslocationname)) return 0;
  if (!option_s_s(bt, &o.locationname)) return 0;
  if (!option_s_s(bt, &o.proxysecret)) return 0;

  if (!option_s_s(bt, &o.dhcpif)) return 0;
  if (!option_s_s(bt, &o.routeif)) return 0;

  if (!option_s_s(bt, &o.macsuffix)) return 0;
  if (!option_s_s(bt, &o.macpasswd)) return 0;

  if (!option_s_s(bt, &o.uamsecret)) return 0;
  if (!option_s_s(bt, &o.uamurl)) return 0;
  if (!option_s_s(bt, &o.uamaaaurl)) return 0;
  if (!option_s_s(bt, &o.uamhomepage)) return 0;
  if (!option_s_s(bt, &o.wisprlogin)) return 0;

  if (!option_s_s(bt, &o.wwwdir)) return 0;
  if (!option_s_s(bt, &o.wwwbin)) return 0;
  if (!option_s_s(bt, &o.uamui)) return 0;
  if (!option_s_s(bt, &o.localusers)) return 0;
#ifdef HAVE_OPENSSL
  if (!option_s_s(bt, &o.sslkeyfile)) return 0;
  if (!option_s_s(bt, &o.sslcertfile)) return 0;
#endif
#ifdef USING_IPC_UNIX
  if (!option_s_s(bt, &o.unixipc)) return 0;
#endif

  if (!option_s_s(bt, &o.adminuser)) return 0;
  if (!option_s_s(bt, &o.adminpasswd)) return 0;
  if (!option_s_s(bt, &o.adminupdatefile)) return 0;
  if (!option_s_s(bt, &o.rtmonfile)) return 0;

  if (!option_s_s(bt, &o.ssid)) return 0;
  if (!option_s_s(bt, &o.vlan)) return 0;
  if (!option_s_s(bt, &o.nasmac)) return 0;
  if (!option_s_s(bt, &o.nasip)) return 0;
  if (!option_s_s(bt, &o.cmdsocket)) return 0;

  if (!option_s_s(bt, &o.uamaliasname)) return 0;

  for (i = 0; i < MAX_UAM_DOMAINS; i++) {
    if (!option_s_s(bt, &o.uamdomains[i])) 
      return 0;
  }

  oldmask = umask(022);

  fd = open(file, O_RDWR | O_TRUNC | O_CREAT, 0666);

  umask(oldmask);

  if (fd <= 0) {

    log_err(errno, "could not save to %s", file);

    return 0;

  } else {
    if (safe_write(fd, &o, sizeof(o)) < 0)
      log_err(errno, "write()");
    size_t len = bt->slen;
    if (safe_write(fd, &len, sizeof(len)) < 0)
      log_err(errno, "write()");
    if (safe_write(fd, bt->data, len) < 0)
      log_err(errno, "write()");
    close(fd);
  }

  return 1;
}

int process_options(int argc, char **argv, int minimal) {

  /*
   *  If ran with arguments besides the load file, then pass
   *  off the arguments to chilli_opt for processing. If chilli_opt
   *  returns true, then we'll also start the server. 
   *
   */

  mode_t process_mask = umask(0077);
  char file[128];
  int i;

  for (i=0; i < argc; i++) {
    if (!strcmp(argv[i],"-b")) {
      if (i+1 < argc) {
	char *file = argv[i+1];
	int fd = open(file, O_RDONLY);
	while (fd > 0) {
	  bstring bt = bfromcstr("");
	  int ok = options_fromfd(fd, bt);
	  if (!ok) bdestroy(bt);
	  return ok;
	}
      }
    }
  }

  snprintf(file,sizeof(file),"/tmp/chilli-%d",getpid());
  
  if (mkdir(file, S_IRWXU | S_IRWXG | S_IRWXO))
    log_err(errno, file);
  
  umask(process_mask);

  return !reload_options(argc, argv);
}

void reprocess_options(int argc, char **argv) {
  opt_run(argc, argv, 1);
}

int reload_options(int argc, char **argv) {
  bstring bt = bfromcstr("");
  int ok = options_load(argc, argv, bt);
  if (!ok) bdestroy(bt);
  return ok;
}

