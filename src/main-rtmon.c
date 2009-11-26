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

#define MAIN_FILE

#include "system.h"
#include <asm/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "net.h"
#include "options.h"
#include "session.h"
#include "dhcp.h"
#include "radius.h"
#include "chilli.h"

struct options_t _options;

static int debug = 0;
static int chilli_pid = 0;
static char * chilli_conf = "/tmp/local.conf";

int main(int argc, char *argv[]) {
  int keep_going = 1;
  int nls = open_netlink();
  int i;

  if (nls < 0) {
    err(1,"netlink");
  }

  for (i=1; i < argc; i++) {
    if (strcmp(argv[i], "-debug")==0) {
      debug = 1;
    } else if (strcmp(argv[i], "-file")==0) {
      chilli_conf = argv[i+1];
    } else if (strcmp(argv[i], "-pid")==0) {
      chilli_pid = atoi(argv[i+1]);
    }
  }

  chilli_signals(&keep_going);

  discover_ifaces();
  discover_routes();

  if (debug) {
    print_ifaces();
    print_routes();
  }

  check_updates();
  
  while (keep_going) {
    read_event(nls);
  }

  return 0;
}
