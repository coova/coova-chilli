/* 
 * Copyright (C) 2007-2010 Coova Technologies, LLC. <support@coova.com>
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

#ifndef _CHILLI_MODULE_H
#define _CHILLI_MODULE_H

struct chilli_module {
  void *lib;
  int (* initialize)      (char *);
  int (* net_select)      (select_ctx *sctx);
  int (* redir_login)     ();
  int (* dhcp_connect)    ();
  int (* dhcp_disconnect) ();
  int (* session_start)   (struct app_conn_t *);
  int (* session_update)  (struct app_conn_t *);
  int (* session_stop)    (struct app_conn_t *);
  int (* destroy)         ();
};

int chilli_module_load(void **ctx, char *name);
int chilli_module_unload(void *ctx);

#define CHILLI_MODULE_INIT 0

#endif
