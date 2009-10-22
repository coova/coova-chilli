/* 
 * Copyright (C) 2009 Coova Technologies, LLC.
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
#ifdef HAVE_OPENSSL
#include "syserr.h"
#include "radius.h"
#include "radius_wispr.h"
#include "radius_chillispot.h"
#include "redir.h"
#include "md5.h"
#include "dhcp.h"
#include "chilli.h"
#include "options.h"
#include "ssl.h"

static openssl_env * sslenv = 0;

openssl_env * initssl() {
  if (sslenv == 0) {
    SSL_library_init();
    if (options()->debug) SSL_load_error_strings();
    SSLeay_add_all_algorithms();
    SSLeay_add_ssl_algorithms();
    openssl_env_init(sslenv = calloc(1, sizeof(openssl_env)), 0);
  }
  return sslenv;
}

static int
openssl_verify_peer_cb(int ok, X509_STORE_CTX *ctx) {
  int err = X509_STORE_CTX_get_error(ctx);
  if (err != X509_V_OK) {
    log_err(errno, "peer certificate error: #%d : %s\n", 
              err, X509_verify_cert_error_string(err));
    return 0;
  }
  return 1;
}

int
openssl_verify_peer(openssl_env *env, int mode) {
  if (!mode) mode = OPENSSL_NO_CERT;
  SSL_CTX_set_verify(env->ctx, mode, openssl_verify_peer_cb);
  return 1;
}

int
openssl_use_certificate(openssl_env *env, char *file) {
  if (file)
    if (SSL_CTX_use_certificate_chain_file(env->ctx, file) > 0)
      return 1;
  log_err(errno, "could not load certificate file %s\n",file);
  return 0;
}

int
openssl_use_privatekey(openssl_env *env, char *file) {
  int err1=-1, err2=-1;
  BIO *bio_err = NULL;
  if (file)
    if ((err1 = SSL_CTX_use_PrivateKey_file(env->ctx, file, SSL_FILETYPE_PEM)) > 0 &&
        (err2 = SSL_CTX_check_private_key(env->ctx)))
      return 1;
  log_err(errno, "could not load private key file %s (%d,%d)\n",file,err1,err2);
  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
  BIO_printf(bio_err,"unable to set private key file\n");
  ERR_print_errors(bio_err);
  return 0;
}

int
openssl_cacert_location(openssl_env *env, char *file, char *dir) {
  int err = SSL_CTX_load_verify_locations(env->ctx, file, dir);
  if (!err)
    log_err(errno, "unable to load CA certificates.\n");
  return err;
}

static RSA *
openssl_tmpRSA_cb(SSL *ssl, int export, int len) {
  openssl_con *con = (openssl_con *)SSL_get_app_data(ssl);
  openssl_env *env = con->env;
  RSA *rsa = 0;

  if (export) {
    /* an export cipher is being used */
    if (len == 512)
      rsa = (RSA *)env->tmpKeys[OPENSSL_TMPKEY_RSA512];
    else if (len == 1024)
      rsa = (RSA *)env->tmpKeys[OPENSSL_TMPKEY_RSA1024];
    else
      /* too expensive to generate on-the-fly, use 1024bit */
      rsa = (RSA *)env->tmpKeys[OPENSSL_TMPKEY_RSA1024];
  }
  else {
    /* sign-only certificate situation exists */
    rsa = (RSA *)env->tmpKeys[OPENSSL_TMPKEY_RSA1024];
  }
  return rsa;
}

static DH *
openssl_tmpDH_cb(SSL *ssl, int export, int len) {
  openssl_con *con = (openssl_con *)SSL_get_app_data(ssl);
  openssl_env *env = con->env;
  DH *dh = 0;

  if (export) {
    /* an export cipher is being used */
    if (len == 512)
      dh = (DH *)env->tmpKeys[OPENSSL_TMPKEY_DH512];
    else if (len == 1024)
      dh = (DH *)env->tmpKeys[OPENSSL_TMPKEY_DH1024];
    else
      /* too expensive to generate on-the-fly, use 1024bit */
      dh = (DH *)env->tmpKeys[OPENSSL_TMPKEY_DH1024];
  }
  else {
    /* sign-only certificate situation exists */
    dh = (DH *)env->tmpKeys[OPENSSL_TMPKEY_DH1024];
  }
  return dh;
}

static void
openssl_tmp_genkeys(openssl_env *env) {

  if ((env->tmpKeys[OPENSSL_TMPKEY_RSA512] = RSA_generate_key(512, RSA_F4, NULL, NULL)) == NULL) {
    log_err(errno, "could not generate tmp 512bit RSA key\n");
  }

  if ((env->tmpKeys[OPENSSL_TMPKEY_RSA1024] = RSA_generate_key(1024, RSA_F4, NULL, NULL)) == NULL) {
    log_err(errno, "could not generate tmp 1024bit RSA key\n");
  }

  if ((env->tmpKeys[OPENSSL_TMPKEY_DH512] = openssl_dh_tmpkey(512)) == NULL) {
    log_err(errno, "could not generate tmp 512bit DH key\n");
  }

  if ((env->tmpKeys[OPENSSL_TMPKEY_DH1024] = openssl_dh_tmpkey(1024)) == NULL) {
    log_err(errno, "could not generate tmp 512bit DH key\n");
  }
}

int
_openssl_env_init(openssl_env *env, char *engine, int server) {
  /*
   * Create an OpenSSL environment (method and context).
   * If ``server'' is 1, the environment is that of a SSL 
   * server.
   */
  if (server) {
    env->meth = SSLv23_server_method();
  } else {
    env->meth = SSLv23_client_method();
  }
  env->ctx = SSL_CTX_new(env->meth);
  SSL_CTX_set_options(env->ctx, SSL_OP_ALL);
  if (engine) {
  retry:
    if ((env->engine = ENGINE_by_id(engine)) == NULL) {
      fprintf(stderr,"invalid engine \"%s\"\n", engine);
      ENGINE_free(env->engine);
      engine = "openssl";
      goto retry;
    }
    if (!ENGINE_set_default(env->engine, ENGINE_METHOD_ALL)) {
      fprintf(stderr,"can't use that engine\n");
      ENGINE_free(env->engine);
      engine = "openssl";
      goto retry;
    }
  }

  SSL_CTX_set_app_data(env->ctx, env);

  if (server) {
    SSL_CTX_set_options(env->ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_session_cache_mode(env->ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_quiet_shutdown(env->ctx, 1);
  }
  return 1;
}

int
openssl_env_init(openssl_env *env, char *engine) {
  int err = _openssl_env_init(env, engine, 1);

  if (!openssl_use_certificate(env, options()->sslcertfile) ||
      !openssl_use_privatekey(env, options()->sslkeyfile))
    return 0;

  return err;
}

openssl_con *
openssl_connect_fd(openssl_env *env, int fd, int timeout) {
  openssl_con *c = (openssl_con *)calloc(1, sizeof(*c));
  if (!c) return 0;
  c->env = env;
  c->con = (SSL *)SSL_new(env->ctx); 
  c->sock = fd;
  c->timeout = timeout;

  SSL_set_app_data(c->con, c);
  if (!SSL_set_fd(c->con, c->sock)) /* error */;
  SSL_set_connect_state(c->con);
  if (!SSL_connect(c->con)) /* error */;
  return c;
}

openssl_con *
openssl_accept_fd(openssl_env *env, int fd, int timeout) {
  openssl_con *c = (openssl_con *)calloc(1, sizeof(*c));
  X509 *peer_cert;
  int rc;

  if (!c) return 0;
  c->env = env;
  c->con = (SSL *)SSL_new(env->ctx); 
  c->sock = fd;
  c->timeout = timeout;

  SSL_clear(c->con);

  SSL_set_app_data(c->con, c);
  if (!SSL_set_fd(c->con, c->sock)) /* error */;
  SSL_set_accept_state(c->con);

  SSL_set_verify_result(c->con, X509_V_OK);

  while (!SSL_is_init_finished(c->con)) {
    if ((rc = SSL_accept(c->con)) <= 0) {
      if (SSL_get_error(c->con, rc) == SSL_ERROR_ZERO_RETURN) {
	log_err(errno, "SSL handshake stopped: connection was closed\n");
	SSL_set_shutdown(c->con, SSL_RECEIVED_SHUTDOWN);
	openssl_free(c);
	return 0;
	/*      } else if (ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) { */
      } else if (SSL_get_error(c->con, rc) == SSL_ERROR_SYSCALL) {
	if (errno == EINTR)
	  continue;
	if (errno > 0)
	  log_err(errno, "SSL handshake interrupted by system [Hint: Stop button pressed in browser?!]");
	else
	  log_err(errno, "Spurious SSL handshake interrupt [Hint: Usually just one of those OpenSSL confusions!?]");
	SSL_set_shutdown(c->con, SSL_RECEIVED_SHUTDOWN);
	openssl_free(c);
	return 0;
      }
      break; 
    }
  }
  
  peer_cert = SSL_get_peer_certificate(c->con);
  if (peer_cert) {
    char subj[1024];

    X509_NAME_oneline(X509_get_subject_name(peer_cert),subj,sizeof(subj));

    if (SSL_get_verify_result(c->con) != X509_V_OK) {
      log_dbg("auth_failed: %s\n", subj);
      X509_free(peer_cert);
      openssl_shutdown(c, 2); 
      openssl_free(c);
      return 0;
    }

    log_dbg("auth_success: %s\n", subj);

    if (options()->debug) {
      EVP_PKEY *pktmp = X509_get_pubkey(peer_cert);
      SSL_CIPHER *cipher;
      char b[512];
      log_dbg("Debugging: SSL Information:\n");
      cipher = SSL_get_current_cipher(c->con);
      log_dbg("  Protocol: %s, %s with %.*s bit key\n", 
	      SSL_CIPHER_get_version(cipher),
	      (char*)SSL_CIPHER_get_name(cipher),
	      sprintf(b, "%d", EVP_PKEY_bits(pktmp)), b);
      log_dbg("  Subject:  %s\n", subj);
      X509_NAME_oneline(X509_get_issuer_name(peer_cert),b,sizeof(b));
      log_dbg("  Issuer:   %s\n", b);
      EVP_PKEY_free(pktmp);
    }

    X509_free(peer_cert);
  }
  return c;
}

int
openssl_error(openssl_con *con, int ret, char *func) {
  int err = -1;
  if (con->con) {
    err = SSL_get_error(con->con, ret);
#if (0)
      fprintf(stderr,"SSL STATUS: (%s()) %s\n", func,
              ((err == SSL_ERROR_NONE) ? "None": 
               ((err == SSL_ERROR_ZERO_RETURN) ? "Return!":
                ((err == SSL_ERROR_WANT_READ) ? "Read (continue)":
                 ((err == SSL_ERROR_WANT_WRITE) ? "Write (continue)":
                  ((err == SSL_ERROR_WANT_X509_LOOKUP) ? "Lookup (continue)":
                   ((err == SSL_ERROR_SYSCALL) ? "Syscall error, abort!":
                    ((err == SSL_ERROR_SSL) ? "SSL error, abort!":
                     "Error"))))))));
#endif
    switch (err) {
    case SSL_ERROR_NONE: return 0;
    case SSL_ERROR_WANT_READ: return 1;
    case SSL_ERROR_WANT_WRITE: return 2;
    case SSL_ERROR_SYSCALL: 
      /*
       * This is a protocol violation, but we got
       * an EOF (remote connection did a shutdown(fd, 1).
       * We will treat it as a zero value.
       */
      if (ret == 0) return 0;
      /* If some other error, fall through */
    case SSL_ERROR_ZERO_RETURN: openssl_shutdown(con, 0);
    case SSL_ERROR_SSL: return -1;
    default: break;
    }
    return 1;
  }
  return err;
}

void
openssl_shutdown(openssl_con *con, int state) {
  int i;
  /*
   * state is the same as in shutdown(2)
   */
  switch(state) {
  case 0: SSL_set_shutdown(con->con, SSL_RECEIVED_SHUTDOWN); break;
  case 1: SSL_set_shutdown(con->con, SSL_SENT_SHUTDOWN); break;
  case 2: SSL_set_shutdown(con->con, SSL_RECEIVED_SHUTDOWN|SSL_SENT_SHUTDOWN); break;
  }
  for (i = 0; i < 4; i++) if (SSL_shutdown(con->con)) break;
}
  
int
openssl_read(openssl_con *con, char *b, int l) {
  int rbytes = 0;
  int err;

  if (!con) return -1;

 repeat_read:

  if (con->timeout && !(SSL_pending(con->con))) {
    fd_set rfds;
    struct timeval tv;
    int fd = con->sock;

    tv.tv_sec = con->timeout;
    tv.tv_usec = 0;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    if (select(fd + 1,&rfds,(fd_set *) 0,(fd_set *) 0,&tv) == -1) return -1;
    if (!FD_ISSET(fd, &rfds)) return 0;
  }
    
  rbytes = SSL_read(con->con, b, l);

  err = openssl_error(con, rbytes, "openssl_read");
  if (rbytes > 0) return rbytes;
  if (err > 0) goto repeat_read;
  return (err == -1)? -1: 0;
}

int
openssl_write(openssl_con *con, char *b, int l) {
  int sent = 0;
  int wrt;
  int err;

  if (con->timeout) {
    fd_set wfds;
    struct timeval tv;
    int fd = con->sock;
    
    tv.tv_sec = con->timeout;
    tv.tv_usec = 0;
    
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    
    if (select(fd + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
    if (!FD_ISSET(fd, &wfds)) return 0;
  }

  while (sent < l) {

  repeat_write:
    
    wrt = SSL_write(con->con, b+sent, l-sent);
    
    if (wrt <= 0) {
      err = openssl_error(con, wrt, "openssl_write");
      if (err == -1) return err;
      else if (err > 0) goto repeat_write;
      break;
    } 

    sent += wrt;
  }

  return sent;
}

void
openssl_free(openssl_con *con) {
  SSL *c = con->con;
  if (c) {
    SSL_set_connect_state(c); 
    SSL_free(c); 
    con->con = 0; 
  }
  free(con);
}

void
openssl_env_free(openssl_env *env) {
  if (env->ctx) SSL_CTX_free(env->ctx);
  if (env->engine) ENGINE_free(env->engine);
  free(env);
}

int 
openssl_pending(openssl_con *con) {
  if (con->con) return SSL_pending(con->con);
  return 0;
}

#endif
