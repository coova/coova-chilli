/* -*- mode: c; c-basic-offset: 2 -*- */
/*
 * Copyright (C) 2007-2012 David Bird (Coova Technologies) <support@coova.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
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

#include "chilli.h"
#include "chilli_module.h"
#include <dlfcn.h>

int chilli_module_load(void **ctx, char *name) {
  struct chilli_module *m = (struct chilli_module *)0;
  char path[512] = "";
  void *lib_handle = NULL;
  char *error = NULL;
  void *sym = NULL;
  int len = 0;

  snprintf(path, sizeof(path), "%s/%s.so",
		_options.moddir ? _options.moddir : DEFLIBDIR, name);

  lib_handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);

  if (!lib_handle) {
    syslog(LOG_ERR, "%s: chilli_module_load() %s", strerror(errno), dlerror());
    return -1;
  }

  snprintf(path, sizeof(path), "%s_module", name);

  len = strlen(path);
  while(len-- > 0)
    if (path[len]=='-')
      path[len] = '_';

  sym = dlsym(lib_handle, path);
  if ((sym == NULL) || ((error = dlerror()) != NULL)) {
    dlclose(lib_handle);
    syslog(LOG_ERR, "%s: %s", strerror(errno), error);
    return -1;
  }

  m = (struct chilli_module *) sym;
  m->lib = lib_handle;

  syslog(LOG_DEBUG, "Loaded module %s", name);

  *ctx = m;

  return 0;
}

int chilli_module_unload(void *ctx) {
  struct chilli_module *m = (struct chilli_module *)ctx;
  dlclose(m->lib);
  return 0;
}
