/* 
 * Tunnel Interface Functions.
 * Copyright (C) 2002, 2003, 2004 Mondru AB.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
 * 
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

/*
 *  A tunnel is the back-haul link which chilli sends traffic. Typically,
 *  this is a single tun/tap interface allowing chilli to simply pass on
 *  packets to the kernel for processing (iptables) and routing. Without the
 *  tun/tap interface, chilli must decide for itself how to route traffic,
 *  maintaining a socket into each back-haul interface. One or more tunnels
 *  are required.
 *
 */

#include "system.h"
#include "tun.h"
#include "ippool.h"
#include "radius.h"
#include "radius_wispr.h"
#include "radius_chillispot.h"
#include "redir.h"
#include "syserr.h"
#include "dhcp.h"
#include "cmdline.h"
#include "chilli.h"
#include "options.h"
#include "net.h"

#define inaddr(x)    (((struct sockaddr_in *)&ifr->x)->sin_addr)
#define inaddr2(p,x) (((struct sockaddr_in *)&(p)->x)->sin_addr)

int tun_discover(struct tun_t *this) {
  net_interface netif;
  struct ifconf ic;
  int fd, len, i;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    log_err(errno, "socket() failed");
    return -1;
  }

  ic.ifc_buf=0;
  ic.ifc_len=0;

  if (ioctl(fd, SIOCGIFCONF, &ic) < 0) {
    log_err(errno, "ioctl(SIOCGIFCONF)");
    close(fd);
    return -1;
  }

  ic.ifc_buf = calloc((size_t)ic.ifc_len, 1);
  if (ioctl(fd, SIOCGIFCONF, &ic) < 0) {
    log_err(errno, "ioctl(SIOCGIFCONF)");
    close(fd);
    return -1;
  }
    
  len = (ic.ifc_len/sizeof(struct ifreq));

  for (i=0; i<len; ++i) {
    struct ifreq *ifr = (struct ifreq *)&ic.ifc_req[i];
    memset(&netif, 0, sizeof(netif));

    /* device name and address */
    strncpy(netif.devname, ifr->ifr_name, sizeof(netif.devname));
    netif.address = inaddr(ifr_addr);

    log_dbg("Interface: %s", ifr->ifr_name);
    log_dbg("\tIP Address:\t%s", inet_ntoa(inaddr(ifr_addr)));


    /* netmask */
    if (-1 < ioctl(fd, SIOCGIFNETMASK, (caddr_t)ifr)) {

      netif.netmask = inaddr(ifr_addr);
      log_dbg("\tNetmask:\t%s", inet_ntoa(inaddr(ifr_addr)));

    } else log_err(errno, "ioctl(SIOCGIFNETMASK)");


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

	  memcpy(netif.hwaddr, u, 6);

	  log_dbg("\tHW Address:\t%2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2x",
		  u[0], u[1], u[2], u[3], u[4], u[5]);
	}
	break;
      }
    } else log_err(errno, "ioctl(SIOCGIFHWADDR)");
#else
#ifdef SIOCGENADDR
    if (-1 < ioctl(fd, SIOCGENADDR, (caddr_t)ifr)) {
      unsigned char *u = (unsigned char *)&ifr->ifr_enaddr;

      memcpy(netif.hwaddr, u, 6);

      log_dbg("\tHW Address:\t%2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2x",
		  u[0], u[1], u[2], u[3], u[4], u[5]);
    } else log_err(errno, "ioctl(SIOCGENADDR)");
#else
#warning Do not know how to find interface hardware address
#endif /* SIOCGENADDR */
#endif /* SIOCGIFHWADDR */


    /* flags */
    if (-1 < ioctl(fd, SIOCGIFFLAGS, (caddr_t)ifr)) {

      netif.devflags = ifr->ifr_flags;

    } else log_err(errno, "ioctl(SIOCGIFFLAGS)");


    /* point-to-point gateway */
    if (netif.devflags & IFF_POINTOPOINT) {
      if (-1 < ioctl(fd, SIOCGIFDSTADDR, (caddr_t)ifr)) {

	netif.gateway = inaddr(ifr_addr);
	log_dbg("\tPoint-to-Point:\t%s", inet_ntoa(inaddr(ifr_dstaddr)));

      } else log_err(errno, "ioctl(SIOCGIFDSTADDR)");
    }


    /* broadcast address */
    if (netif.devflags & IFF_BROADCAST) {
      if (-1 < ioctl(fd, SIOCGIFBRDADDR, (caddr_t)ifr)) {
	
	netif.broadcast = inaddr(ifr_addr);
	log_dbg("\tBroadcast:\t%s", inet_ntoa(inaddr(ifr_addr)));
	
      } else log_err(errno, "ioctl(SIOCGIFBRDADDR)");
    }


    /* mtu */
    if (-1 < ioctl(fd, SIOCGIFMTU, (caddr_t)ifr)) {
      
      netif.mtu = ifr->ifr_mtu;
      log_dbg("\tMTU:      \t%u",  ifr->ifr_mtu);
      
    } else log_err(errno, "ioctl(SIOCGIFMTU)");
    

    /* if (0 == ioctl(fd, SIOCGIFMETRIC, ifr)) */

    if (netif.address.s_addr == htonl(INADDR_LOOPBACK) ||
        netif.address.s_addr == INADDR_ANY ||
        netif.address.s_addr == INADDR_NONE)
      continue;

    else {
      net_interface *newif = tun_nextif(tun);

      if (newif) {
	int idx = newif->idx;
	memcpy(newif, &netif, sizeof(netif));
	newif->idx = idx;

	net_open(newif);


      switch(newif->idx) {
      default:
	/* memcpy(newif->gwaddr, options()->nexthop, PKT_ETH_ALEN);*/
	break;
      }

	if (!strcmp(options()->routeif, netif.devname))
	  tun->routeidx = newif->idx;
      } else {
	log_dbg("no room for interface %s", netif.devname);
      }
    }
  }

  close(fd);
  return 0;
}

net_interface * tun_nextif(struct tun_t *tun) {
  net_interface *netif;

  if (tun->_interface_count == TUN_MAX_INTERFACES)
    return 0;

  netif = &tun->_interfaces[tun->_interface_count];
  netif->idx = tun->_interface_count;

  tun->_interface_count++;

  return netif;
}

int tun_name2idx(struct tun_t *tun, char *name) {
  int i;

  for (i=0; i<tun->_interface_count; i++) 
    if (!strcmp(name, tun->_interfaces[i].devname))
      return i;

  return 0; /* tun/tap index */
}

#if defined(__linux__)

int tun_nlattr(struct nlmsghdr *n, int nsize, int type, void *d, size_t dlen) {
  size_t len = RTA_LENGTH(dlen);
  size_t alen = NLMSG_ALIGN(n->nlmsg_len);
  struct rtattr *rta = (struct rtattr*) (((void*)n) + alen);
  if (alen + len > nsize)
    return -1;
  rta->rta_len = len;
  rta->rta_type = type;
  memcpy(RTA_DATA(rta), d, dlen);
  n->nlmsg_len = alen + len;
  return 0;
}

int tun_gifindex(struct tun_t *this, uint32_t *index) {
  struct ifreq ifr;
  int fd;

  memset (&ifr, '\0', sizeof (ifr));
  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;
  ifr.ifr_netmask.sa_family = AF_INET;
  strncpy(ifr.ifr_name, tuntap(this).devname, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ-1] = 0; /* Make sure to terminate */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    log_err(errno, "socket() failed");
  }
  if (ioctl(fd, SIOCGIFINDEX, &ifr)) {
    log_err(errno,"ioctl() failed");
    close(fd);
    return -1;
  }
  close(fd);
  *index = ifr.ifr_ifindex;
  return 0;
}
#endif

int tun_addaddr(struct tun_t *this, struct in_addr *addr,
		struct in_addr *dstaddr, struct in_addr *netmask) {

#if defined(__linux__)
  struct {
    struct nlmsghdr 	n;
    struct ifaddrmsg 	i;
    char buf[TUN_NLBUFSIZE];
  } req;
  
  struct sockaddr_nl local;
  size_t addr_len;
  int fd;
  int status;
  
  struct sockaddr_nl nladdr;
  struct iovec iov;
  struct msghdr msg;

  if (!this->addrs) /* Use ioctl for first addr to make ping work */
    return tun_setaddr(this, addr, dstaddr, netmask);

  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
  req.n.nlmsg_type = RTM_NEWADDR;
  req.i.ifa_family = AF_INET;
  req.i.ifa_prefixlen = 32; /* 32 FOR IPv4 */
  req.i.ifa_flags = 0;
  req.i.ifa_scope = RT_SCOPE_HOST; /* TODO or 0 */

  if (tun_gifindex(this, &req.i.ifa_index)) {
    log_err(errno,"tun_gifindex() failed");
    return -1;
  }

  tun_nlattr(&req.n, sizeof(req), IFA_ADDRESS, addr, sizeof(addr));
  tun_nlattr(&req.n, sizeof(req), IFA_LOCAL, dstaddr, sizeof(dstaddr));

  if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
    log_err(errno,"socket() failed");
    return -1;
  }

  memset(&local, 0, sizeof(local));
  local.nl_family = AF_NETLINK;
  local.nl_groups = 0;
  
  if (bind(fd, (struct sockaddr*)&local, sizeof(local)) < 0) {
    log_err(errno, "bind() failed");
    close(fd);
    return -1;
  }

  addr_len = sizeof(local);
  if (getsockname(fd, (struct sockaddr*)&local, (socklen_t *) &addr_len) < 0) {
    log_err(errno, "getsockname() failed");
    close(fd);
    return -1;
  }

  if (addr_len != sizeof(local)) {
    log_err(0, "Wrong address length %d", addr_len);
    close(fd);
    return -1;
  }

  if (local.nl_family != AF_NETLINK) {
    log_err(0, "Wrong address family %d", local.nl_family);
    close(fd);
    return -1;
  }
  
  iov.iov_base = (void*)&req.n;
  iov.iov_len = req.n.nlmsg_len;

  msg.msg_name = (void*)&nladdr;
  msg.msg_namelen = sizeof(nladdr),
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_pid = 0;
  nladdr.nl_groups = 0;

  req.n.nlmsg_seq = 0;
  req.n.nlmsg_flags |= NLM_F_ACK;

  status = sendmsg(fd, &msg, 0); 

  dev_set_flags(tuntap(this).devname, IFF_UP | IFF_RUNNING); 

  close(fd);
  this->addrs++;

  return 0;

#elif defined (__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)

  int fd;
  struct ifaliasreq      areq;

  /* TODO: Is this needed on FreeBSD? */
  if (!this->addrs) /* Use ioctl for first addr to make ping work */
    return tun_setaddr(this, addr, dstaddr, netmask); /* TODO dstaddr */

  memset(&areq, 0, sizeof(areq));

  /* Set up interface name */
  strncpy(areq.ifra_name, tuntap(this).devname, IFNAMSIZ);
  areq.ifra_name[IFNAMSIZ-1] = 0; /* Make sure to terminate */

  ((struct sockaddr_in*) &areq.ifra_addr)->sin_family = AF_INET;
  ((struct sockaddr_in*) &areq.ifra_addr)->sin_len = sizeof(areq.ifra_addr);
  ((struct sockaddr_in*) &areq.ifra_addr)->sin_addr.s_addr = addr->s_addr;

  ((struct sockaddr_in*) &areq.ifra_mask)->sin_family = AF_INET;
  ((struct sockaddr_in*) &areq.ifra_mask)->sin_len    = sizeof(areq.ifra_mask);
  ((struct sockaddr_in*) &areq.ifra_mask)->sin_addr.s_addr = netmask->s_addr;

  /* For some reason FreeBSD uses ifra_broadcast for specifying dstaddr */
  ((struct sockaddr_in*) &areq.ifra_broadaddr)->sin_family = AF_INET;
  ((struct sockaddr_in*) &areq.ifra_broadaddr)->sin_len = sizeof(areq.ifra_broadaddr);
  ((struct sockaddr_in*) &areq.ifra_broadaddr)->sin_addr.s_addr = dstaddr->s_addr;

  /* Create a channel to the NET kernel. */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    log_err(errno,
	    "socket() failed");
    return -1;
  }
  
  if (ioctl(fd, SIOCAIFADDR, (void *) &areq) < 0) {
    log_err(errno,
	    "ioctl(SIOCAIFADDR) failed");
    close(fd);
    return -1;
  }

  close(fd);
  this->addrs++;
  return 0;

#elif defined (__sun__)
  
  if (!this->addrs) /* Use ioctl for first addr to make ping work */
    return tun_setaddr(this, addr, dstaddr, netmask);
  
  log_err(errno, "Setting multiple addresses not possible on Solaris");
  return -1;

#else
#error  "Unknown platform!"
#endif
}

int tun_setaddr(struct tun_t *this, struct in_addr *addr, struct in_addr *dstaddr, struct in_addr *netmask) {
  net_set_address(&tuntap(this), addr, dstaddr, netmask);
  
#if defined(__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)
  net_add_route(dstaddr, addr, netmask);
  this->routes = 1;
#endif

  return 0;
}

int tuntap_interface(struct _net_interface *netif) {
#if defined(__linux__)
  struct ifreq ifr;

#elif defined(__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)
  char devname[IFNAMSIZ+5]; /* "/dev/" + ifname */
  int devnum;
  struct ifaliasreq areq;
  int fd;

#elif defined(__sun__)
  int if_fd, ppa = -1;
  static int ip_fd = 0;
  int muxid;
  struct ifreq ifr;

#else
#error  "Unknown platform!"
#endif

  memset(netif, 0, sizeof(*netif));

  /*  memcpy(netif->gwaddr, options()->nexthop, PKT_ETH_ALEN);*/

#if defined(__linux__)
  /* Open the actual tun device */
  if ((netif->fd  = open("/dev/net/tun", O_RDWR)) < 0) {
    log_err(errno, "open() failed");
    return -1;
  }
  
  /* Set device flags. For some weird reason this is also the method
     used to obtain the network interface name */
  memset(&ifr, 0, sizeof(ifr));

  /* Tun device, no packet info */
  ifr.ifr_flags = (options()->usetap ? IFF_TAP|IFF_PROMISC : IFF_TUN) | IFF_NO_PI; 
#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
  ifr.ifr_flags |= IFF_ONE_QUEUE;
#endif

  if (options()->tundev && *options()->tundev && 
      strcmp(options()->tundev, "tap") && strcmp(options()->tundev, "tun"))
    strncpy(ifr.ifr_name, options()->tundev, IFNAMSIZ);

  if (ioctl(netif->fd, TUNSETIFF, (void *) &ifr) < 0) {
    log_err(errno, "ioctl() failed");
    close(netif->fd);
    return -1;
  } 
  
#if defined(IFF_ONE_QUEUE) && defined(SIOCSIFTXQLEN)
  {
    struct ifreq nifr;
    int nfd;
    memset(&nifr, 0, sizeof(nifr));
    if ((nfd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0) {
      strncpy(nifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
      nifr.ifr_qlen = options()->txqlen;

      if (ioctl(nfd, SIOCSIFTXQLEN, (void *) &nifr) >= 0) 
	log_info("TX queue length set to %d", options()->txqlen);
      else 
	log_err(errno, "Cannot set tx queue length on %s", ifr.ifr_name);

      close (nfd);
    } else {
      log_err(errno, "Cannot open socket on %s", ifr.ifr_name);
    }
  }
#endif
  
  strncpy(netif->devname, ifr.ifr_name, IFNAMSIZ);
  netif->devname[IFNAMSIZ-1] = 0;
  
  ioctl(netif->fd, TUNSETNOCSUM, 1); /* Disable checksums */

  /* Get the MAC address of our tap interface */
  if (options()->usetap) {
    int fd;
    netif->flags |= NET_ETHHDR;
    if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0) {
      memset(&ifr, 0, sizeof(ifr));
      strncpy(ifr.ifr_name, netif->devname, IFNAMSIZ);
      if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
	log_err(errno, "ioctl(d=%d, request=%d) failed", fd, SIOCGIFHWADDR);
      }
      memcpy(netif->hwaddr, ifr.ifr_hwaddr.sa_data, PKT_ETH_ALEN);
      log_dbg("tap-mac: %s %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", ifr.ifr_name,
	      netif->hwaddr[0],netif->hwaddr[1],netif->hwaddr[2],
	      netif->hwaddr[3],netif->hwaddr[4],netif->hwaddr[5]);
      close(fd);
    }
  }

  return 0;
  
#elif defined(__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)

  /* Find suitable device */
  for (devnum = 0; devnum < 255; devnum++) { /* TODO 255 */ 
    snprintf(devname, sizeof(devname), "/dev/tun%d", devnum);
    if ((netif->fd = open(devname, O_RDWR)) >= 0) break;
    if (errno != EBUSY) break;
  } 
  if (netif->fd < 0) {
    log_err(errno, "Can't find tunnel device");
    return -1;
  }

  snprintf(netif->devname, sizeof(netif->devname), "tun%d", devnum);

  /* The tun device we found might have "old" IP addresses allocated */
  /* We need to delete those. This problem is not present on Linux */

  memset(&areq, 0, sizeof(areq));

  /* Set up interface name */
  strncpy(areq.ifra_name, netif->devname, sizeof(areq.ifra_name));

  /* Create a channel to the NET kernel. */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    log_err(errno,"socket() failed");
    return -1;
  }
  
  /* Delete any IP addresses until SIOCDIFADDR fails */
  while (ioctl(fd, SIOCDIFADDR, (void *) &areq) != -1);

  close(fd);
  return 0;

#elif defined(__sun__)

  if( (ip_fd = open("/dev/udp", O_RDWR, 0)) < 0){
    log_err(errno, "Can't open /dev/udp");
    return -1;
  }
  
  if( (netif->fd = open("/dev/tun", O_RDWR, 0)) < 0){
    log_err(errno, "Can't open /dev/tun");
    return -1;
  }
  
  /* Assign a new PPA and get its unit number. */
  if( (ppa = ioctl(netif->fd, TUNNEWPPA, -1)) < 0){
    log_err(errno, "Can't assign new interface");
    return -1;
  }
  
  if( (if_fd = open("/dev/tun", O_RDWR, 0)) < 0){
    log_err(errno, "Can't open /dev/tun (2)");
    return -1;
  }
  if(ioctl(if_fd, I_PUSH, "ip") < 0){
    log_err(errno, "Can't push IP module");
    return -1;
  }
  
  /* Assign ppa according to the unit number returned by tun device */
  if(ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0){
    log_err(errno, "Can't set PPA %d", ppa);
    return -1;
  }

  /* Link the two streams */
  if ((muxid = ioctl(ip_fd, I_LINK, if_fd)) < 0) {
    log_err(errno, "Can't link TUN device to IP");
    return -1;
  }

  close (if_fd);
  
  snprintf(netif->devname, sizeof(netif->devname), "tun%d", ppa);
  netif->devname[sizeof(netif->devname)-1] = 0;

  memset(&ifr, 0, sizeof(ifr));
  strcpy(ifr.ifr_name, netif->devname);
  ifr.ifr_ip_muxid = muxid;
  
  if (ioctl(ip_fd, SIOCSIFMUXID, &ifr) < 0) {
    ioctl(ip_fd, I_PUNLINK, muxid);
    log_err(errno, "Can't set multiplexor id");
    return -1;
  }
  
  /*  if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0)
      msg (M_ERR, "Set file descriptor to non-blocking failed"); */

  return 0;

#else
#error  "Unknown platform!"
#endif

}

int tun_new(struct tun_t **ptun) {
  struct tun_t *tun;

  if (!(tun = *ptun = calloc(1, sizeof(struct tun_t)))) {
    log_err(errno, "calloc() failed");
    return EOF;
  }

  tuntap_interface(tun_nextif(tun));

  if (options()->routeif) {
    tun_discover(tun);
  }

  return 0;
}

int tun_free(struct tun_t *tun) {

  if (tun->routes) {
#warning fix this
    /*XXX: todo! net_delete_route(&tuntap(tun)); */
  }

  tun_close(tun);

  /* TODO: For solaris we need to unlink streams */

  free(tun);
  return 0;
}

int tun_set_cb_ind(struct tun_t *this, 
		   int (*cb_ind) (struct tun_t *tun, void *pack, size_t len, int idx)) {
  this->cb_ind = cb_ind;
  return 0;
}

int tun_decaps(struct tun_t *this, int idx) {

#if defined(__linux__) || defined (__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)
  unsigned char buffer[PACKET_MAX];
  ssize_t status;

  if ((status = net_read(&tun(this, idx), buffer, sizeof(buffer))) <= 0) {
    log_err(errno, "read() failed");
    return -1;
  }

  if (this->debug)  
    log_dbg("tun_decaps(%d) %s",status,tun(tun,idx).devname);

  if (0) { /* if we wanted to do nat'ing, it would could be done here */
    struct in_addr a;
    struct pkt_iphdr_t *iph = (struct pkt_iphdr_t *)buffer;
    inet_aton("10.1.0.1", &a);
    iph->daddr = a.s_addr;
    chksum(iph);
  }

   if (this->cb_ind)
#if defined (__OpenBSD__)
    /* tun interface adds 4 bytes to front of packet under OpenBSD */
     return this->cb_ind(this, buffer+4, status-4, idx);
#else
     return this->cb_ind(this, buffer, status, idx);
#endif

  return 0;

#elif defined (__sun__)
  unsigned char buffer[PACKET_MAX];
  struct strbuf sbuf;
  int f = 0;
  
  sbuf.maxlen = PACKET_MAX;      
  sbuf.buf = buffer;
  if (getmsg(tun(this, idx).fd, NULL, &sbuf, &f) < 0) {
    log_err(errno, "getmsg() failed");
    return -1;
  }

  if (this->cb_ind)
    return this->cb_ind(this, &packet, sbuf.len);
  return 0;
  
#endif
}

/*
static uint32_t dnatip[1024];
static uint16_t dnatport[1024];
*/

int tun_write(struct tun_t *tun, uint8_t *pack, size_t len, int idx) {
#if defined (__OpenBSD__)

  unsigned char buffer[PACKET_MAX+4];

  /* Can we user writev here to be more efficient??? */
  *((uint32_t *)(&buffer))=htonl(AF_INET);
  memcpy(&buffer[4], pack, len);

  return net_write(&tun(tun, idx), buffer, len+4);

#elif defined(__linux__) || defined (__FreeBSD__) || defined (__APPLE__) || defined (__NetBSD__)

  return net_write(&tun(tun, idx), pack, len);

#elif defined (__sun__)

  struct strbuf sbuf;
  sbuf.len = len;      
  sbuf.buf = pack;
  return putmsg(tun(tun, idx).fd, NULL, &sbuf, 0);

#endif
}

int tun_encaps(struct tun_t *tun, uint8_t *pack, size_t len, int idx) {

  pkt_shape(pack, &len);

  if (tun(tun, idx).flags & NET_ETHHDR) {
    uint8_t *gwaddr = options()->nexthop; /*tun(tun, idx).gwaddr;*/
    struct pkt_ethhdr_t *ethh = (struct pkt_ethhdr_t *)pack;
    /* memcpy(ethh->src, tun(tun, idx).hwaddr, PKT_ETH_ALEN); */

    if (gwaddr[0] == 0 && gwaddr[1] == 0 && gwaddr[2] == 0 && 
	gwaddr[3] == 0 && gwaddr[4] == 0 && gwaddr[5] == 0) {
      /*  
       *  If there isn't a 'nexthop' (gwaddr) for the interface,
       *  default to the tap interface's MAC instead, so that the kernel
       *  will route it. 
       */
      gwaddr = tun(tun, idx).hwaddr;
    }

    memcpy(ethh->dst, gwaddr, PKT_ETH_ALEN);

    log_dbg("writing to tap src=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x dst=%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
	    ethh->src[0],ethh->src[1],ethh->src[2],ethh->src[3],ethh->src[4],ethh->src[5],
	    ethh->dst[0],ethh->dst[1],ethh->dst[2],ethh->dst[3],ethh->dst[4],ethh->dst[5]);

    if (0) { /* if we wanted to do nat'ing we could do it here */
      struct _net_interface *netif = &tun(tun, idx);
      struct pkt_iphdr_t *iph = (struct pkt_iphdr_t *)(pack + PKT_ETH_HLEN);
      iph->saddr = netif->address.s_addr;
      chksum(iph);
    }

  } else {
    size_t ethlen = sizeofeth(pack);
    pack += ethlen;
    len  -= ethlen;
  }

  /* log_dbg("tun_encaps(%d) %s",len,tun(tun,idx).devname);*/

  return tun_write(tun, pack, len, idx);
}

int tun_runscript(struct tun_t *tun, char* script) {
  char saddr[TUN_ADDRSIZE];
  char smask[TUN_ADDRSIZE];
  char b[TUN_ADDRSIZE];
  struct in_addr net;
  int status;

  net.s_addr = tuntap(tun).address.s_addr & tuntap(tun).netmask.s_addr;

  if ((status = fork()) < 0) {
    log_err(errno, "fork() returned -1!");
    return 0;
  }
  
  if (status > 0) { /* Parent */
    return 0;
  }
  
/*
#ifdef HAVE_CLEARENV
  if (clearenv() != 0) {
    log_err(errno,
	    "clearenv() did not return 0!");
    exit(0);
  }
#endif
*/
  
  if (setenv("DEV", tuntap(tun).devname, 1) != 0) {
    log_err(errno, "setenv() did not return 0!");
    exit(0);
  }

  strncpy(saddr, inet_ntoa(tuntap(tun).address), sizeof(saddr));
  saddr[sizeof(saddr)-1] = 0;
  if (setenv("ADDR", saddr, 1 ) != 0) {
    log_err(errno, "setenv() did not return 0!");
    exit(0);
  }

  strncpy(smask, inet_ntoa(tuntap(tun).netmask), sizeof(smask));
  smask[sizeof(smask)-1] = 0;
  if (setenv("MASK", smask, 1) != 0) {
    log_err(errno, "setenv() did not return 0!");
    exit(0);
  }

  strncpy(b, inet_ntoa(net), sizeof(b));
  b[sizeof(b)-1] = 0;
  if (setenv("NET", b, 1 ) != 0) {
    log_err(errno, "setenv() did not return 0!");
    exit(0);
  }

  snprintf(b, sizeof(b), "%d", options()->uamport);
  if (setenv("UAMPORT", b, 1 ) != 0) {
    log_err(errno, "setenv() did not return 0!");
    exit(0);
  }

  snprintf(b, sizeof(b), "%d", options()->uamuiport);
  if (setenv("UAMUIPORT", b, 1 ) != 0) {
    log_err(errno, "setenv() did not return 0!");
    exit(0);
  }

  if (setenv("DHCPIF", options()->dhcpif ? options()->dhcpif : "", 1 ) != 0) {
    log_err(errno, "setenv() did not return 0!");
    exit(0);
  }

  if (execl(script, script, tuntap(tun).devname, saddr, smask, (char *) 0) != 0) {
    log_err(errno, "execl() did not return 0!");
    exit(0);
  }
  
  exit(0);
}


/* Currently unused 
int tun_addroute2(struct tun_t *this,
		  struct in_addr *dst,
		  struct in_addr *gateway,
		  struct in_addr *mask) {
  
  struct {
    struct nlmsghdr 	n;
    struct rtmsg 	r;
    char buf[TUN_NLBUFSIZE];
  } req;
  
  struct sockaddr_nl local;
  int addr_len;
  int fd;
  int status;
  struct sockaddr_nl nladdr;
  struct iovec iov;
  struct msghdr msg;

  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
  req.n.nlmsg_type = RTM_NEWROUTE;
  req.r.rtm_family = AF_INET;
  req.r.rtm_table  = RT_TABLE_MAIN;
  req.r.rtm_protocol = RTPROT_BOOT;
  req.r.rtm_scope  = RT_SCOPE_UNIVERSE;
  req.r.rtm_type  = RTN_UNICAST;
  tun_nlattr(&req.n, sizeof(req), RTA_DST, dst, 4);
  tun_nlattr(&req.n, sizeof(req), RTA_GATEWAY, gateway, 4);
  
  if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
	    "socket() failed");
    return -1;
  }

  memset(&local, 0, sizeof(local));
  local.nl_family = AF_NETLINK;
  local.nl_groups = 0;
  
  if (bind(fd, (struct sockaddr*)&local, sizeof(local)) < 0) {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
	    "bind() failed");
    close(fd);
    return -1;
  }

  addr_len = sizeof(local);
  if (getsockname(fd, (struct sockaddr*)&local, &addr_len) < 0) {
    sys_err(LOG_ERR, __FILE__, __LINE__, errno,
	    "getsockname() failed");
    close(fd);
    return -1;
  }

  if (addr_len != sizeof(local)) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
	    "Wrong address length %d", addr_len);
    close(fd);
    return -1;
  }

  if (local.nl_family != AF_NETLINK) {
    sys_err(LOG_ERR, __FILE__, __LINE__, 0,
	    "Wrong address family %d", local.nl_family);
    close(fd);
    return -1;
  }
  
  iov.iov_base = (void*)&req.n;
  iov.iov_len = req.n.nlmsg_len;

  msg.msg_name = (void*)&nladdr;
  msg.msg_namelen = sizeof(nladdr),
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_pid = 0;
  nladdr.nl_groups = 0;

  req.n.nlmsg_seq = 0;
  req.n.nlmsg_flags |= NLM_F_ACK;

  status = sendmsg(fd, &msg, 0);  * TODO: Error check *
  close(fd);
  return 0;
}
*/

