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

#ifndef _SSL_H_
#define _SSL_H_
#include "system.h"

#ifdef HAVE_SSL

#ifdef HAVE_MATRIXSSL
#include "matrixssl.h"

typedef struct {

  sslKeys_t* keys;
  char ready;

} openssl_env;

#endif

#ifdef HAVE_OPENSSL
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/engine.h>

#define OPENSSL_TMPKEY_RSA512   0
#define OPENSSL_TMPKEY_RSA1024  1
#define OPENSSL_TMPKEY_DH512    2
#define OPENSSL_TMPKEY_DH1024   3
#define OPENSSL_TMPKEY_MAX      4

#define OPENSSL_NO_CERT      (SSL_VERIFY_NONE)
#define OPENSSL_REQUEST_CERT (SSL_VERIFY_PEER)
#define OPENSSL_REQUIRE_CERT (SSL_VERIFY_PEER|\
                              SSL_VERIFY_CLIENT_ONCE|\
                              SSL_VERIFY_FAIL_IF_NO_PEER_CERT)

typedef struct {
  SSL_METHOD *meth;
  SSL_CTX *ctx;
  ENGINE *engine;
  void *tmpKeys[OPENSSL_TMPKEY_MAX];
  char ready;
} openssl_env;

#endif

typedef struct {
  openssl_env *env;
  SSL *con;
  int sock;
  int timeout;
} openssl_con;

openssl_env * initssl();
int openssl_verify_peer(openssl_env *env, int mode);
int openssl_use_certificate(openssl_env *env, char *file);
int openssl_use_privatekey(openssl_env *env, char *file);
int openssl_cacert_location(openssl_env *env, char *file, char *dir);
int openssl_env_init(openssl_env *env, char *engine, int server);
openssl_con *openssl_connect_fd(openssl_env *env, int fd, int timeout);
openssl_con *openssl_accept_fd(openssl_env *env, int fd, int timeout);
int openssl_error(openssl_con *con, int ret, char *func);
void openssl_shutdown(openssl_con *con, int state);
int openssl_read(openssl_con *con, char *b, int l, int t);
int openssl_write(openssl_con *con, char *b, int l, int t);
void openssl_free(openssl_con *con);
void openssl_env_free(openssl_env *env);
int openssl_pending(openssl_con *con);

#endif
#endif
