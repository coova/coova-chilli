
#include "chilli.h"
#include "chilli_module.h"
#include <dlfcn.h>

int chilli_module_load(void **ctx, char *name) {
  struct chilli_module *m;
  char path[512];
  void *lib_handle;
  char *error;
  void *sym;

  safe_snprintf(path, sizeof(path), "%s/%s.so", 
		_options.moddir ? _options.moddir : DEFLIBDIR, name);
  
  lib_handle = dlopen(path, RTLD_LAZY);
  if (!lib_handle) {
    log_err(errno, "chilli_module_load() %s", dlerror);
    return -1;
  }

  safe_snprintf(path, sizeof(path), "%s_module", name);
  
  sym = dlsym(lib_handle, path);
  if ((error = dlerror()) != NULL) {
    dlclose(lib_handle);
    log_err(errno, "%s", error);
    return -1;
  }

  m = (struct chilli_module *) sym;
  m->lib = lib_handle;

  log_dbg("Loaded module %s", name);

  *ctx = m;
  
  return 0;
}

int chilli_module_unload(void *ctx) {
  struct chilli_module *m = (struct chilli_module *)ctx;
  dlclose(m->lib);
  return 0;
}

#ifdef TEST
int main(int argc, char **argv) {
  void *lib_handle;
  double (*fn)(int *);
  int x;
  char *error;
  
  lib_handle = dlopen("/tmp/sample.so", RTLD_LAZY);
  if (!lib_handle) {
    fprintf(stderr, "%s\n", dlerror());
    exit(1);
  }
  
  fn = dlsym(lib_handle, "ctest1");
  if ((error = dlerror()) != NULL) {
    fprintf(stderr, "%s\n", error);
    exit(1);
  }
  
  (*fn)(&x);
  printf("Valx=%d\n",x);
  
  dlclose(lib_handle);
  return 0;
}
#endif

