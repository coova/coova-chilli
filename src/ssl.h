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
#include "system.h"
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
} openssl_env;

typedef struct {
  openssl_env *env;
  SSL *con;
  int sock;
  int timeout;
} openssl_con;

#endif
