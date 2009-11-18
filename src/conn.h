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

#ifndef _CONN_H
#define _CONN_H

#include "system.h"
#include "net.h"
#ifdef HAVE_OPENSSL
#include "ssl.h"
#endif

struct conn_t;

typedef int (*conn_handler)(struct conn_t *, void *ctx);

struct conn_t {
  struct sockaddr_in peer;

  int sock;
  bstring write_buf;
  int write_pos;

#ifdef HAVE_OPENSSL
  openssl_con * sslcon;
#endif

  conn_handler read_handler;
  void * read_handler_ctx;
  conn_handler done_handler;
  void * done_handler_ctx;
};

int conn_update(struct conn_t *conn, fd_set *r, fd_set *w, fd_set *e);
void conn_bstring_readhandler(struct conn_t *conn, bstring data);
void conn_set_readhandler(struct conn_t *conn, conn_handler handler, void *ctx);
void conn_set_donehandler(struct conn_t *conn, conn_handler handler, void *ctx);

int conn_setup(struct conn_t *conn, char *hostname, int port, bstring bwrite);
void conn_finish(struct conn_t *conn);

int conn_fd(struct conn_t *conn, fd_set *r, fd_set *w, fd_set *e, int *m);
int conn_close(struct conn_t *conn);

void conn_bstring_readhandler(struct conn_t *conn, bstring data);

#endif
