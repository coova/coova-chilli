
#include "chilli.h"
#include "chilli_module.h"

#define SOCK_PATH "/tmp/echo"

static int fd = 0;

static int acc(void *nullData, int sock) {
  int rlen;
  char req[512];

  if ((rlen = safe_read(fd, req, sizeof(req))) < 0) {
    log_err(errno, "acc()/read()");
    return -1;
  }

  log_dbg("Received echo %.*s", rlen, req);

  return 0;
}

static int module_initialize(char *conf) {
  struct sockaddr_un local;
  
  log_dbg("%s", __FUNCTION__);
  if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {

    log_err(errno, "could not allocate UNIX Socket!");

  } else {

    local.sun_family = AF_UNIX;

    strcpy(local.sun_path, SOCK_PATH);
    unlink(local.sun_path);

    if (bind(fd, (struct sockaddr *)&local, 
	     sizeof(struct sockaddr_un)) == -1) {
      log_err(errno, "could bind UNIX Socket!");
      close(fd);
      fd = 0;
    }
  }

  return 0;
}

static int module_net_select(select_ctx *sctx) {
  log_dbg("%s", __FUNCTION__);
  net_select_reg(sctx, fd, SELECT_READ, (select_callback) acc, 0, 0);
  return 0;
}

static int module_redir_login() {
  log_dbg("%s", __FUNCTION__);
  return 0;
}

static int module_dhcp_connect(struct app_conn_t *appconn, 
			       struct dhcp_conn_t *dhcpconn) {
  log_dbg("%s", __FUNCTION__);
  return 0;
}

static int module_dhcp_disconnect(struct app_conn_t *appconn, 
				  struct dhcp_conn_t *dhcpconn) {
  log_dbg("%s", __FUNCTION__);
  return 0;
}

static int module_session_start(struct app_conn_t *appconn) {
  log_dbg("%s", __FUNCTION__);
  return 0;
}

static int module_session_update(struct app_conn_t *appconn) {
  log_dbg("%s", __FUNCTION__);
  return 0;
}

static int module_session_stop(struct app_conn_t *appconn) {
  log_dbg("%s", __FUNCTION__);
  return 0;
}

static int module_destroy() {
  close(fd);
  return 0;
}

struct chilli_module sample_module = {
  CHILLI_MODULE_INIT,
  module_initialize, 
  module_net_select,
  module_redir_login,
  module_dhcp_connect,
  module_dhcp_disconnect,
  module_session_start,
  module_session_update,
  module_session_stop,
  module_destroy,
};

