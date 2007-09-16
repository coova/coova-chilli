/*
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
 *
 */

#ifndef _SYSTEM_H
#define _SYSTEM_H

#include "../config.h"

/*
 *   I do not like this here, but otherwise
 *   __u64 is not defined. Set by -ansi
 */

#undef __STRICT_ANSI__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/un.h>

#if defined(__linux__)
#include <asm/types.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#elif defined (__FreeBSD__)  || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__) 
#include <net/if.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <ifaddrs.h>
#endif

#ifndef EIDRM
#define EIDRM   EINVAL
#endif
#ifndef ENOMSG
#define ENOMSG  EAGAIN
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if defined(HAVE_NET_IF_H) && !defined(__linux__)
#include <net/if.h>
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif

#ifdef MTRACE
#include <mcheck.h> 
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

#undef LITTLE_ENDIAN
#undef BIG_ENDIAN

#if (defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN) || \
    (defined(i386) || defined(__i386__) || defined(__i486__) || \
     defined(__i586__) || defined(__i686__) || defined(vax) || defined(MIPSEL))
# define LITTLE_ENDIAN 1
# define BIG_ENDIAN 0
#elif (defined(__BYTE_ORDER) && defined(__BIG_ENDIAN) && __BYTE_ORDER == __BIG_ENDIAN) || \
      (defined(sparc) || defined(POWERPC) || defined(mc68000) || defined(sel))
# define LITTLE_ENDIAN 0
# define BIG_ENDIAN 1
#else
# define LITTLE_ENDIAN 0
# define BIG_ENDIAN 0
#endif

#include "bstrlib.h"

#endif
