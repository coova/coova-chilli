/* 
 *
 * Syslog functions.
 * Copyright (C) 2003, 2004 Mondru AB.
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#ifndef _SYSERR_H
#define _SYSERR_H

#define SYSERR_MSGSIZE 256

void sys_err(int pri, char *filename, int line, int en, const char *fmt, ...);
void sys_errpack(int pri, char *fn, int ln, int en, struct sockaddr_in *peer,
		 void *pack, unsigned len, char *fmt, ...);

#define log(p,fmt,args...)      sys_err(p,           __FILE__,__LINE__,0,fmt,## args)
#define log_dbg(fmt,args...)    if (options() && options()->debug) {\
                                sys_err(LOG_DEBUG,   __FILE__,__LINE__,0,fmt,## args); }
#define log_warn(e,fmt,args...) sys_err(LOG_WARNING, __FILE__,__LINE__,e,fmt,## args)
#define log_info(fmt,args...)   sys_err(LOG_NOTICE,  __FILE__,__LINE__,0,fmt,## args)
#define log_err(e,fmt,args...)  sys_err(LOG_ERR,     __FILE__,__LINE__,e,fmt,## args)

#endif	/* !_SYSERR_H */
