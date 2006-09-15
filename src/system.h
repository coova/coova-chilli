/*
 * Copyright (c) 2006 Coova Technologies Ltd
 *
 */

#ifndef _SYSTEM_H
#define _SYSTEM_H

#include "../config.h"

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <resolv.h> 
#include <stdarg.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
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

#elif defined (__FreeBSD__)  || defined (__APPLE__)
#include <net/if.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_tun.h>
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

#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#ifdef MTRACE
#include <mcheck.h> 
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#endif
