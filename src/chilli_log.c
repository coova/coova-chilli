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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>
#include <assert.h>
#include "chilli_log.h"

#define CHILLI_LOG_LEVEL \
((CHILLI_LOG != NULL && CHILLI_LOG->log_init) == 0 ? 9 : \
((CHILLI_LOG != NULL && CHILLI_LOG->log_init > 1) ? \
  CHILLI_LOG->log_level : chilli_log_default->log_level))

/**
 * @brief      Log a message to log.
 *
 * @param[in]  level      { parameter_description }
 * @param[in]  fmt        { parameter_description }
 * @param[in]  <unnamed>  { parameter_description }
 */
void chilli_log(unsigned level, char const *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  chilli_vllog(CHILLI_LOG, level, fmt, ap);
  va_end(ap);
}

 /**
  * @brief      Log a message with level.
  *
  * @param[in]  log        { parameter_description }
  * @param[in]  level      { parameter_description }
  * @param[in]  fmt        { parameter_description }
  * @param[in]  ...        { parameter_description }
  */
void chilli_llog(chilli_log_t *log, unsigned level, char const *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  chilli_vllog(log, level, fmt, ap);
  va_end(ap);
}

/**
 * @brief      Log a message with level (stdarg version).
 *
 * @param[in]  log    { parameter_description }
 * @param[in]  level  { parameter_description }
 * @param[in]  fmt    { parameter_description }
 * @param[in]  ap     { parameter_description }
 */
void chilli_vllog(chilli_log_t *log, unsigned level, char const *fmt, va_list ap)
{
  chilli_logger_f *logger = NULL;

  assert(log);

  if (!log->log_init)
    chilli_log_init(log);

  if (log->log_init > 1 ? level > log->log_level : level > chilli_log_default->log_level) {
    return;
  }

  logger = log->log_logger;

  if (!logger) {
    logger = chilli_log_default->log_logger;
  }

  if (logger)
    logger(level, fmt, ap);
}

/**
 * @brief      Initialize a log
 *
 * @param      log   Log context
 */
void chilli_log_init(chilli_log_t *log)
{
  char *env = NULL;

  if (log->log_init)
    return;

  if (log != chilli_log_default && !chilli_log_default->log_init)
    chilli_log_init(chilli_log_default);

  if (log->log_env && (env = getenv(log->log_env))) {
    int level = atoi(env);

    log->log_level = level;
    log->log_init = 2;
  }
  else {
    log->log_level = log->log_default;
    log->log_init = 1;
  }
}

 /**
  * @brief      Set log level.
  * 
  * The function chilli_log_set_level() sets the logging level.  The log events
  * have certain level (0..9); if logging level is lower than the level of
  * the event, the log message is ignored.
  * If @a log is NULL, the default log level is changed.
  *
  * @param[in]  log    log context
  * @param[in]  level  Log level
  * 
  */
void chilli_log_set_level(chilli_log_t *log, unsigned level)
{
  if (log == NULL)
    log = chilli_log_default;

  log->log_level = level;
  log->log_init = 2;

  chilli_llog(log, LOG_DEBUG, "%s: set log to level %u\n", log->log_name, log->log_level);
}

/**
 * @brief Redirect a log.
 *
 * The function chilli_log_redirect() redirects the chilli_log() output to
 * @a logger function. The @a logger function has following prototype:
 *
 * @code
 * void logger(void *logarg, char const *format, va_list ap);
 * @endcode
 *
 * If @a logger is NULL, the default logger will be used. If @a log is NULL,
 * the default logger is changed.
 */
void chilli_log_redirect(chilli_log_t *log, chilli_logger_f *logger, void *logarg)
{
  if (log == NULL)
    log = chilli_log_default;

  log->log_logger = logger;
  log->log_stream = logarg;
}
