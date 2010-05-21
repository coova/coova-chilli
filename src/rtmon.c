/* 
 * Copyright (C) 2007-2010 Coova Technologies, LLC. <support@coova.com>
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
#include <asm/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "chilli.h"

#define MYPROTO NETLINK_ROUTE
#define MYMGRP RTMGRP_IPV4_ROUTE

#define inaddr(x)    (((struct sockaddr_in *)&ifr->x)->sin_addr)
#define inaddr2(p,x) (((struct sockaddr_in *)&(p)->x)->sin_addr)

struct netlink_req {
  struct nlmsghdr nlmsg_info;
  struct rtmsg rtmsg_info;
  char buffer[2048];
};

static int netlink_route_request(int fd) {
  struct sockaddr_nl local;
  struct sockaddr_nl peer;   
  struct msghdr msg_info;
  struct netlink_req req;
  struct iovec iov_info;
  int rtn;

  bzero(&local, sizeof(local));
  local.nl_family = AF_NETLINK;
  local.nl_pad = 0;
  local.nl_pid = getpid() + 1;
  local.nl_groups = 0;

  if (bind(fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
    perror("bind");
    return -1;
  }
  
  bzero(&peer, sizeof(peer));
  peer.nl_family = AF_NETLINK;
  peer.nl_pad = 0;
  peer.nl_pid = 0;
  peer.nl_groups = 0;
  
  bzero(&msg_info, sizeof(msg_info));
  msg_info.msg_name = (void *) &peer;
  msg_info.msg_namelen = sizeof(peer);
  
  bzero(&req, sizeof(req));
  
  req.nlmsg_info.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.nlmsg_info.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nlmsg_info.nlmsg_type = RTM_GETROUTE;
  
  req.rtmsg_info.rtm_family = AF_INET;
  req.rtmsg_info.rtm_table = RT_TABLE_MAIN;
  
  iov_info.iov_base = (void *) &req.nlmsg_info;
  iov_info.iov_len = req.nlmsg_info.nlmsg_len;
  msg_info.msg_iov = &iov_info;
  msg_info.msg_iovlen = 1;
  
  rtn = sendmsg(fd, &msg_info, 0);
  if (rtn < 0) {
    perror("sendmsg");
    return -1;
  }
  return 0;
}

static int netlink_route_results(int fd, char *b, size_t blen) {
  int len = 0;

  bzero(b, blen);

  while (blen > 0) {
    int rtn = recv(fd, b, blen, 0);

    if (rtn < 0) {
      perror("recv");
      break;
    }

    struct nlmsghdr *hdr = (struct nlmsghdr *) b;
    
    if (hdr->nlmsg_type == NLMSG_DONE)	{
      break;
    }

    b += rtn;
    blen -= rtn;
    len += rtn;
  }

  return len;
}

/**
* Extract each route table entry and print
*/
static void netlink_parse_routes(struct rtmon_t *rtmon, char *b, int blen) {
  struct nlmsghdr *hdr = (struct nlmsghdr *) b;
  struct rtattr * attr;
  int payload;
  int idx = 0;

  for(; NLMSG_OK(hdr, blen); hdr = NLMSG_NEXT(hdr, blen), idx++) {
    struct rtmsg * rtm = (struct rtmsg *) NLMSG_DATA(hdr);

    if (rtm->rtm_table != RT_TABLE_MAIN)
      continue;

    attr = (struct rtattr *) RTM_RTA(rtm);
    payload = RTM_PAYLOAD(hdr);

    for (;RTA_OK(attr, payload); attr = RTA_NEXT(attr, payload)) {
      switch(attr->rta_type) {
      case RTA_DST:
	rtmon->_routes[idx].destination = *(struct in_addr *)RTA_DATA(attr);
	break;
      case RTA_GATEWAY:
	rtmon->_routes[idx].gateway = *(struct in_addr *)RTA_DATA(attr);
	break;
      case RTA_OIF:
	rtmon->_routes[idx].if_index = *((int *) RTA_DATA(attr));
      default:
	break; 
      }
    }

    {
      rtmon->_routes[idx].has_data = 1;
      uint32_t mask = 0;
      int i;
      for (i=0; i<rtm->rtm_dst_len; i++) {
	mask |= (1 << (32-i-1));
      }
      rtmon->_routes[idx].netmask.s_addr = htonl(mask);
    }
  }
}

struct msgnames_t {
  int id;
  char *msg;
} typenames[] = {
#define MSG(x) { x, #x }
  MSG(RTM_NEWROUTE),
  MSG(RTM_DELROUTE),
  MSG(RTM_GETROUTE),
#undef MSG
  {0,0}
};

static char *lookup_name(struct msgnames_t *db,int id) {
  static char name[512];
  struct msgnames_t *msgnamesiter;
  for (msgnamesiter=db;msgnamesiter->msg;++msgnamesiter) {
    if (msgnamesiter->id == id)
      break;
  }
  if (msgnamesiter->msg) {
    return msgnamesiter->msg;
  }
  snprintf(name,sizeof(name),"#%i\n",id);
  return name;
}

int rtmon_open_netlink() {
  int sock = socket(AF_NETLINK, SOCK_RAW, MYPROTO);
  struct sockaddr_nl addr;
  
  memset((void *)&addr, 0, sizeof(addr));
  
  if (sock<0)
    return sock;

  addr.nl_family = AF_NETLINK;
  addr.nl_pid = getpid();
  addr.nl_groups = MYMGRP;

  if (bind(sock,(struct sockaddr *)&addr,sizeof(addr)) < 0)
    return -1;

  return sock;
}

void print_ifaces(struct rtmon_t *rtmon) {
  int i;
  for (i=0; i < MAX_IFACES; i++) {
    if (rtmon->_ifaces[i].has_data) {
      unsigned char *u = rtmon->_ifaces[i].hwaddr;
      log_dbg("Interface(%d)[ifindex=%d]: %s\n", i, rtmon->_ifaces[i].index, rtmon->_ifaces[i].devname);
      log_dbg("IP Address:\t%s\n", inet_ntoa(rtmon->_ifaces[i].address));
      log_dbg("Network:\t%s\n", inet_ntoa(rtmon->_ifaces[i].network));
      log_dbg("Netmask:\t%s\n", inet_ntoa(rtmon->_ifaces[i].netmask));
      log_dbg("Broadcast:\t%s\n", inet_ntoa(rtmon->_ifaces[i].broadcast));
      log_dbg("Point-to-Point:\t%s\n", inet_ntoa(rtmon->_ifaces[i].gateway));
      log_dbg("HW Address:\t%2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2x\n",
	      u[0], u[1], u[2], u[3], u[4], u[5]);
      log_dbg("MTU:      \t%u\n",  rtmon->_ifaces[i].mtu);
    }
  }
}

void print_routes(struct rtmon_t *rtmon) {
  int i;
  for (i=0; i < MAX_ROUTES; i++) {
    if (rtmon->_routes[i].has_data) {
      log_dbg("Route(%d)[-> ifindex=%d]\n", i, rtmon->_routes[i].if_index);
      log_dbg("Destination:\t%s\n", inet_ntoa(rtmon->_routes[i].destination));
      log_dbg("Netmask:\t%s\n", inet_ntoa(rtmon->_routes[i].netmask));
      log_dbg("Gateway:\t%s\n", inet_ntoa(rtmon->_routes[i].gateway));
    }
  }
}

static const char *mactoa(uint8_t *m) {
  static char buff[256];
  sprintf(buff, "%02x:%02x:%02x:%02x:%02x:%02x",
	  m[0], m[1], m[2], m[3], m[4], m[5]);
  return (buff);
}

void check_updates(struct rtmon_t *rtmon, rtmon_callback func) {
  int i, j;
  for (i=0; i < MAX_ROUTES; i++) {
    if (rtmon->_routes[i].has_data) {
      if (rtmon->_routes[i].destination.s_addr == 0) {

	log_dbg("Default Route %s\n", inet_ntoa(rtmon->_routes[i].gateway));

	for (j=0; j < MAX_IFACES; j++) {
	  if (rtmon->_ifaces[j].has_data) {
	    if (rtmon->_routes[i].if_index == rtmon->_ifaces[j].index) {
	      struct arpreq areq;
	      struct sockaddr_in *sin;
	      int s, attempt=0, retries=3;
	      
	      log_dbg("Route Interface %s\n", rtmon->_ifaces[j].devname);

	      if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		return;
	      }

	      memset(&areq, 0, sizeof(areq));
	      sin = (struct sockaddr_in *) &areq.arp_pa;

	      sin->sin_family = AF_INET;
	      sin->sin_addr.s_addr = rtmon->_routes[i].gateway.s_addr;

	      strncpy(areq.arp_dev, rtmon->_ifaces[j].devname, sizeof(areq.arp_dev));

	      while (attempt < retries) {
		struct sockaddr_in addr;
		char b[1];
		
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr = sin->sin_addr;
		addr.sin_port = htons(10000);
		
		if (sendto(s, b, sizeof(b), 0,
			   (struct sockaddr *) &addr, 
			   sizeof(addr)) < 0)
		  perror("sendto");

		if (ioctl(s, SIOCGARP, (caddr_t) &areq) == -1) {

		  if (errno == ENXIO) {
		    log_dbg("%s -- no entry\n", inet_ntoa(sin->sin_addr));
		    attempt++;
		    sleep(1);
		    continue;
		  }
		  else { perror("SIOCGARP"); break; }

		} else {

		  log_dbg("MAC %s\n", mactoa((uint8_t *)&areq.arp_ha.sa_data));
		  memcpy(rtmon->_routes[i].gwaddr, &areq.arp_ha.sa_data, sizeof(rtmon->_routes[i].gwaddr));

		  if (func(rtmon, &rtmon->_ifaces[j], &rtmon->_routes[i]))
		    log_err(errno, "callback failed");

		  break;
		}
	      }

	      close(s);
	      return;
	    }
	  }
	}
      }
    }
  }
}

void discover_ifaces(struct rtmon_t *rtmon) {
  struct ifconf ic;
  int fd, len, i;
  
  memset(&rtmon->_ifaces, 0, sizeof(rtmon->_ifaces));
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return;
  }
  
  ic.ifc_buf=0;
  ic.ifc_len=0;
    
  if (ioctl(fd, SIOCGIFCONF, &ic) < 0) {
    close(fd);
    return;
  }
  
  ic.ifc_buf = calloc((size_t)ic.ifc_len, 1);
  if (ioctl(fd, SIOCGIFCONF, &ic) < 0) {
    close(fd);
    return;
  }
  
  len = (ic.ifc_len/sizeof(struct ifreq));
  
  for (i=0; i < len; ++i) {
    struct ifreq *ifr = (struct ifreq *)&ic.ifc_req[i];
    int idx = i;
    
    rtmon->_ifaces[idx].has_data = 1;
    
    /* device name and address */
    strncpy(rtmon->_ifaces[idx].devname, ifr->ifr_name, sizeof(rtmon->_ifaces[idx].devname));
    rtmon->_ifaces[idx].address = inaddr(ifr_addr);
    
    /* index */
    if (-1 < ioctl(fd, SIOCGIFINDEX, (caddr_t) ifr)) {
      rtmon->_ifaces[idx].index = ifr->ifr_ifindex;
    }
    
    /* netmask */
    if (-1 < ioctl(fd, SIOCGIFNETMASK, (caddr_t)ifr)) {
      rtmon->_ifaces[idx].netmask = inaddr(ifr_addr);
    } 
    
    rtmon->_ifaces[idx].network.s_addr = 
      rtmon->_ifaces[idx].address.s_addr & 
      rtmon->_ifaces[idx].netmask.s_addr;
    
    /* hardware address */
#ifdef SIOCGIFHWADDR
    if (-1 < ioctl(fd, SIOCGIFHWADDR, (caddr_t)ifr)) {
      switch (ifr->ifr_hwaddr.sa_family) {
      case  ARPHRD_NETROM:  
      case  ARPHRD_ETHER:  
      case  ARPHRD_PPP:
      case  ARPHRD_EETHER:  
      case  ARPHRD_IEEE802: 
	{
	  unsigned char *u = (unsigned char *)&ifr->ifr_addr.sa_data;
	  memcpy(rtmon->_ifaces[idx].hwaddr, u, 6);
	}
	break;
      }
    } 
#else
#ifdef SIOCGENADDR
    if (-1 < ioctl(fd, SIOCGENADDR, (caddr_t)ifr)) {
      unsigned char *u = (unsigned char *)&ifr->ifr_enaddr;
      memcpy(rtmon->_ifaces[idx].hwaddr, u, 6);
    } 
#else
#warning Do not know how to find interface hardware address
#endif /* SIOCGENADDR */
#endif /* SIOCGIFHWADDR */
    
    
    /* flags */
    if (-1 < ioctl(fd, SIOCGIFFLAGS, (caddr_t)ifr)) {
      rtmon->_ifaces[i].devflags = ifr->ifr_flags;
    } 
    
    /* point-to-point gateway */
    if (rtmon->_ifaces[i].devflags & IFF_POINTOPOINT) {
      if (-1 < ioctl(fd, SIOCGIFDSTADDR, (caddr_t)ifr)) {
	rtmon->_ifaces[i].gateway = inaddr(ifr_addr);
      } 
    }
    
    /* broadcast address */
    if (rtmon->_ifaces[i].devflags & IFF_BROADCAST) {
      if (-1 < ioctl(fd, SIOCGIFBRDADDR, (caddr_t)ifr)) {
	rtmon->_ifaces[i].broadcast = inaddr(ifr_addr);
      } 
    }
    
    if (-1 < ioctl(fd, SIOCGIFMTU, (caddr_t)ifr)) {
      rtmon->_ifaces[i].mtu = ifr->ifr_mtu;
    } 
  }
  
  close(fd);
}

void discover_routes(struct rtmon_t *rtmon) {
  int fd;
  char b[8192];
  int blen;
  
  memset(&rtmon->_routes, 0, sizeof(rtmon->_routes));

  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  
  if (fd < 0) {
    perror("Error in sock open");
    return;
  }
  
  netlink_route_request(fd);
  blen = netlink_route_results(fd, b, sizeof(b));
  netlink_parse_routes(rtmon, b, blen);
  
  close(fd);
}

int rtmon_read_event(struct rtmon_t *rtmon, rtmon_callback func) {
  struct sockaddr_nl nladdr;
  struct msghdr msg;
  struct iovec iov[2];
  struct nlmsghdr nlh;
  char buffer[65536];
  int ret;

  iov[0].iov_base = (void *)&nlh;
  iov[0].iov_len = sizeof(nlh);
  iov[1].iov_base = (void *)buffer;
  iov[1].iov_len = sizeof(buffer);

  msg.msg_name = (void *)&(nladdr);
  msg.msg_namelen = sizeof(nladdr);
  msg.msg_iov = iov;
  msg.msg_iovlen = sizeof(iov)/sizeof(iov[0]);

  ret = recvmsg(rtmon->fd, &msg, 0);

  if (ret < 0) {
    return ret;
  }

  log_dbg("Type: %i (%s)\n",(nlh.nlmsg_type),lookup_name(typenames,nlh.nlmsg_type));

#define FLAG(x) if (nlh.nlmsg_flags & x) printf(" %s",#x)
  FLAG(NLM_F_REQUEST);
  FLAG(NLM_F_MULTI);
  FLAG(NLM_F_ACK);
  FLAG(NLM_F_ECHO);
  FLAG(NLM_F_REPLACE);
  FLAG(NLM_F_EXCL);
  FLAG(NLM_F_CREATE);
  FLAG(NLM_F_APPEND);
#undef FLAG

  log_dbg("\nSeq : %i\nPid : %i\n\n",nlh.nlmsg_seq,nlh.nlmsg_pid);

  discover_ifaces(rtmon);
  discover_routes(rtmon);

  if (_options.debug) {
    print_ifaces(rtmon);
    print_routes(rtmon);
  }

  check_updates(rtmon, func);
  
  return 0;
}

