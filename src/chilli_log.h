/* -*- mode: c; c-basic-offset: 2 -*- */
/*
Copyright (c) Mondru AB, David Bird (Coova Technologies)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name(s) of the above-listed copyright holder(s) nor the
   names of its contributors may be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _CHILLI_LOG_H
#define _CHILLI_LOG_H

#include <stdarg.h>

typedef struct chilli_log_s chilli_log_t;

/** Initialize a su_log_t structure */
#define CHILLI_LOG_INIT(name, env, level) \
  { sizeof(chilli_log_t), name, env, level, LOG_DEBUG, 0, NULL, NULL, }

typedef void (chilli_logger_f)(int level, char const *fmt, va_list ap);

struct chilli_log_s {
  int             log_size;
  char const      *log_name;
  char const      *log_env;
  unsigned        log_default;
  unsigned        log_level;
  int             log_init;

  chilli_logger_f *log_logger;
  void            *log_stream;
};

#ifndef CHILLI_LOG
#define CHILLI_LOG       (chilli_log_default)
#else
extern chilli_log_t CHILLI_LOG[];
#endif

extern chilli_log_t chilli_log_default[];

void chilli_log_init(chilli_log_t *log);

void chilli_log_set_level(chilli_log_t *log, unsigned level);

void chilli_log_redirect(chilli_log_t *log, chilli_logger_f *f, void *stream);

void chilli_vllog(chilli_log_t *log, unsigned level, char const *fmt, va_list ap);

void chilli_llog(chilli_log_t *log, unsigned level, char const *fmt, ...) __attribute__ ((__format__ (printf, 3, 4)));

void chilli_log(unsigned level, char const *fmt, ...)  __attribute__ ((__format__ (printf, 2, 3)));

#endif /* _CHILLI_LOG_H */
