/* 
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (C) 2007-2009 Coova Technologies, LLC. <support@coova.com>
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
#include "syserr.h"
#include "options.h"
#include "net.h"

int dev_set_flags(char const *dev, int flags) {
  struct ifreq ifr;
  int fd;
  
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ-1] = 0; /* Make sure to terminate */

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    log_err(errno,"socket() failed");
    return -1;
  }

  if (ioctl(fd, SIOCSIFFLAGS, &ifr)) {
    log_err(errno,"ioctl(SIOCSIFFLAGS) failed");
    close(fd);
    return -1;
  }

  close(fd);

  return 0;
}

int dev_get_flags(char const *dev, int *flags) {
  struct ifreq ifr;
  int fd;
  
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ-1] = 0; 

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    log_err(errno, "socket() failed");
    return -1;
  }

  if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
    log_err(errno, "ioctl(SIOCSIFFLAGS) failed");
    close(fd);
    return -1;
  }

  close(fd);

  *flags = ifr.ifr_flags;

  return 0;
}

int dev_set_address(char const *devname, struct in_addr *address, 
		    struct in_addr *dstaddr, struct in_addr *netmask) {
  struct ifreq ifr;
  int fd;

  memset (&ifr, 0, sizeof (ifr));
  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;

#if defined(__linux__)
  ifr.ifr_netmask.sa_family = AF_INET;

#elif defined(__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)
  ((struct sockaddr_in *) &ifr.ifr_addr)->sin_len = sizeof (struct sockaddr_in);
  ((struct sockaddr_in *) &ifr.ifr_dstaddr)->sin_len = sizeof (struct sockaddr_in);
#endif

  strncpy(ifr.ifr_name, devname, IFNAMSIZ);
  ifr.ifr_name[IFNAMSIZ-1] = 0; /* Make sure to terminate */

  /* Create a channel to the NET kernel. */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    log_err(errno, "socket() failed");
    return -1;
  }

  if (address) { /* Set the interface address */
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = address->s_addr;
    if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
      if (errno != EEXIST) {
	log_err(errno, "ioctl(SIOCSIFADDR) failed");
      }
      else {
	log_warn(errno, "ioctl(SIOCSIFADDR): Address already exists");
      }
      close(fd);
      return -1;
    }
  }

  if (dstaddr) { /* Set the destination address */
    ((struct sockaddr_in *) &ifr.ifr_dstaddr)->sin_addr.s_addr = dstaddr->s_addr;
    if (ioctl(fd, SIOCSIFDSTADDR, (caddr_t) &ifr) < 0) {
      log_err(errno, "ioctl(SIOCSIFDSTADDR) failed");
      close(fd);
      return -1; 
    }
  }

  if (netmask) { /* Set the netmask */
#if defined(__linux__)
    ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr.s_addr =  netmask->s_addr;

#elif defined(__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr =  netmask->s_addr;

#elif defined(__sun__)
    ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr =  netmask->s_addr;
#else
#error  "Unknown platform!" 
#endif

    if (ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
      log_err(errno, "ioctl(SIOCSIFNETMASK) failed");
      close(fd);
      return -1;
    }
  }
  
  close(fd);
  
  return dev_set_flags(devname, IFF_UP | IFF_RUNNING); 
}

int net_init(net_interface *netif, char *ifname, uint16_t protocol, int promisc, uint8_t *mac) {
  memset(netif, 0, sizeof(net_interface));
  strncpy(netif->devname, ifname, IFNAMSIZ);
  netif->devname[IFNAMSIZ] = 0;
  netif->protocol = protocol;

  if (promisc) {
    netif->flags |= NET_PROMISC;
  }
  
  if (mac) {
    netif->flags |= NET_USEMAC;
    memcpy(netif->hwaddr, mac, PKT_ETH_ALEN);
  }
  
  return net_open(netif);
}

int net_open(net_interface *netif) {
  net_close(netif);
  net_gflags(netif);

  if (!(netif->devflags & IFF_UP) || !(netif->devflags & IFF_RUNNING)) {
    struct in_addr noaddr;
    net_sflags(netif, netif->devflags | IFF_NOARP);
    memset(&noaddr, 0, sizeof(noaddr));
    dev_set_address(netif->devname, &noaddr, NULL, NULL);
  }

  return net_open_eth(netif);
}

int net_reopen(net_interface *netif) {
  net_close(netif);
  return net_open(netif);
}

int net_set_address(net_interface *netif, struct in_addr *address, 
		    struct in_addr *dstaddr, struct in_addr *netmask) {
  netif->address.s_addr = address->s_addr;
  netif->gateway.s_addr = dstaddr->s_addr;
  netif->netmask.s_addr = netmask->s_addr;

  return dev_set_address(netif->devname, address, dstaddr, netmask);
}

ssize_t net_read(net_interface *netif, void *d, size_t dlen) {
  ssize_t len;
  
  if ((len = read(netif->fd, d, dlen)) < 0) {
#ifdef ENETDOWN
    if (errno == ENETDOWN) {
      net_reopen(netif);
    }
#endif
    log_err(errno, "read(fd=%d, len=%d) == %d", netif->fd, dlen, len);
    return -1;
  }

  return len;
}

ssize_t net_write(net_interface *netif, void *d, size_t dlen) {
  ssize_t len;
  
  if ((len = write(netif->fd, d, dlen)) < 0) {
#ifdef ENETDOWN
    if (errno == ENETDOWN) {
      net_reopen(netif);
    }
#endif
    log_err(errno, "write(fd=%d, len=%d) failed", netif->fd, dlen);
    return -1;
  }

  return len;
}

int net_set_mtu(net_interface *netif, size_t mtu) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
  ifr.ifr_mtu = mtu;
  if (ioctl(netif->fd, SIOCSIFMTU, &ifr) < 0) {
    log_err(errno, "ioctl(d=%d, request=%d) failed", netif->fd, SIOCSIFMTU);
    return -1;
  }
  return 0;
}

int net_route(struct in_addr *dst, struct in_addr *gateway, struct in_addr *mask, int delete) {

  /* TODO: solaris!  */

#if defined(__linux__)
  struct rtentry r;
  int fd;

  memset (&r, 0, sizeof (r));
  r.rt_flags = RTF_UP | RTF_GATEWAY; /* RTF_HOST not set */

  /* Create a channel to the NET kernel. */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    log_err(errno, "socket() failed");
    return -1;
  }

  r.rt_dst.sa_family     = AF_INET;
  r.rt_gateway.sa_family = AF_INET;
  r.rt_genmask.sa_family = AF_INET;
  ((struct sockaddr_in *) &r.rt_dst)->sin_addr.s_addr = dst->s_addr;
  ((struct sockaddr_in *) &r.rt_gateway)->sin_addr.s_addr = gateway->s_addr;
  ((struct sockaddr_in *) &r.rt_genmask)->sin_addr.s_addr = mask->s_addr;
  
  if (delete) {
    if (ioctl(fd, SIOCDELRT, (void *) &r) < 0) {
      log_err(errno,"ioctl(SIOCDELRT) failed");
      close(fd);
      return -1;
    }
  }
  else {
    if (ioctl(fd, SIOCADDRT, (void *) &r) < 0) {
      log_err(errno, "ioctl(SIOCADDRT) failed");
      close(fd);
      return -1;
    }
  }
  close(fd);
  return 0;
  
#elif defined(__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)

  struct {
    struct rt_msghdr rt;
    struct sockaddr_in dst;
    struct sockaddr_in gate;
    struct sockaddr_in mask;
  } req;
  
  int fd;
  struct rt_msghdr *rtm;
  
  if ((fd = socket(AF_ROUTE, SOCK_RAW, 0)) == -1) {
    log_err(errno, "socket() failed");
    return -1;
  }
  
  memset(&req, 0, sizeof(req));
  
  rtm  = &req.rt;
  
  rtm->rtm_msglen = sizeof(req);
  rtm->rtm_version = RTM_VERSION;
  if (delete) {
    rtm->rtm_type = RTM_DELETE;
  }
  else {
    rtm->rtm_type = RTM_ADD;
  }
  rtm->rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;  /* TODO */
  rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
  rtm->rtm_pid = getpid();      
  rtm->rtm_seq = 0044;                                 /* TODO */
  
  req.dst.sin_family       = AF_INET;
  req.dst.sin_len          = sizeof(req.dst);
  req.mask.sin_family      = AF_INET;
  req.mask.sin_len         = sizeof(req.mask);
  req.gate.sin_family      = AF_INET;
  req.gate.sin_len         = sizeof(req.gate);
  
  req.dst.sin_addr.s_addr  = dst->s_addr;
  req.mask.sin_addr.s_addr = mask->s_addr;
  req.gate.sin_addr.s_addr = gateway->s_addr;
  
  if (write(fd, rtm, rtm->rtm_msglen) < 0) {
    log_err(errno, "write() failed");
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
  
#elif defined(__sun__)
  log_err(errno, "Could not set up routing on Solaris. Please add route manually.");
  return 0;
#else
#error  "Unknown platform!"
#endif
}

#if defined(__linux__)

/**
 * Opens an Ethernet interface. As an option the interface can be set in
 * promisc mode. If not null macaddr and ifindex are filled with the
 * interface mac address and index
 **/
int net_open_eth(net_interface *netif) {
  struct ifreq ifr;
  struct packet_mreq mr;
  struct sockaddr_ll sa;
  int option = 1;

  memset(&ifr, 0, sizeof(ifr));

  /* Create socket */
  if ((netif->fd = socket(PF_PACKET, SOCK_RAW, htons(netif->protocol))) < 0) {
    if (errno == EPERM) {
      log_err(errno, "Cannot create raw socket. Must be root.");
    }

    log_err(errno, "socket(domain=%d, type=%lx, protocol=%d) failed",
	    PF_PACKET, SOCK_RAW, netif->protocol);

    return -1;
  }

  /* Enable reception and transmission of broadcast frames */
  if (setsockopt(netif->fd, SOL_SOCKET, SO_BROADCAST, &option, sizeof(option)) < 0) {
    log_err(errno, "setsockopt(s=%d, level=%d, optname=%d, optlen=%d) failed",
	    netif->fd, SOL_SOCKET, SO_BROADCAST, sizeof(option));
    return -1;
  }
  
  /* Get the MAC address of our interface */
  strncpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
  if (ioctl(netif->fd, SIOCGIFHWADDR, (caddr_t)&ifr) < 0) {
    log_err(errno, "ioctl(d=%d, request=%d) failed", netif->fd, SIOCGIFHWADDR);
    return -1;
  }

  if (ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {

    netif->flags |= NET_ETHHDR;

    if ((netif->flags & NET_USEMAC) == 0) {
      memcpy(netif->hwaddr, ifr.ifr_hwaddr.sa_data, PKT_ETH_ALEN);
    } else {
      strncpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
      memcpy(ifr.ifr_hwaddr.sa_data, netif->hwaddr, PKT_ETH_ALEN);
      if (ioctl(netif->fd, SIOCSIFHWADDR, (caddr_t)&ifr) < 0) {
	log_err(errno, "ioctl(d=%d, request=%d) failed", netif->fd, SIOCSIFHWADDR);
	return -1;
      }
    }
  }
  
  if (netif->hwaddr[0] & 0x01) {
    log_err(0, "Ethernet has broadcast or multicast address: %.16s", netif->devname);
  }
  
  /* Get the current interface address, network, and any destination address */
  
  /* Verify that MTU = ETH_DATA_LEN */
  strncpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
  if (ioctl(netif->fd, SIOCGIFMTU, (caddr_t)&ifr) < 0) {
    log_err(errno, "ioctl(d=%d, request=%d) failed", netif->fd, SIOCGIFMTU);
    return -1;
  }
  if (ifr.ifr_mtu != ETH_DATA_LEN) {
    log_err(0, "MTU does not match EHT_DATA_LEN: %d %d", ifr.ifr_mtu, ETH_DATA_LEN);
    return -1;
  }
  
  /* Get ifindex */
  strncpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
  if (ioctl(netif->fd, SIOCGIFINDEX, (caddr_t)&ifr) < 0) {
    log_err(errno, "ioctl(SIOCFIGINDEX) failed");
  }
  netif->ifindex = ifr.ifr_ifindex;
  
  /* Set interface in promisc mode */
  if (netif->flags & NET_PROMISC) {

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
    if (ioctl(netif->fd, SIOCGIFFLAGS, (caddr_t)&ifr) == -1) {
      log_err(errno, "ioctl(SIOCGIFFLAGS)");
    } else {
      netif->devflags = ifr.ifr_flags;
      ifr.ifr_flags |= IFF_PROMISC;
      if (ioctl (netif->fd, SIOCSIFFLAGS, (caddr_t)&ifr) == -1) {
	log_err(errno, "Could not set flag IFF_PROMISC");
      }
    }

    memset(&mr,0,sizeof(mr));
    mr.mr_ifindex = netif->ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(netif->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (char *)&mr, sizeof(mr)) < 0) {
      log_err(errno, "setsockopt(s=%d, level=%d, optname=%d, optlen=%d) failed",
	      netif->fd, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, sizeof(mr));
      return -1;
    }
  }

  /* Bind to particular interface */
  memset(&sa, 0, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(netif->protocol);
  sa.sll_ifindex = netif->ifindex;

  if (bind(netif->fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
    log_err(errno, "bind(sockfd=%d) failed", netif->fd);
    return -1;
  }

  return 0;
}

#elif defined (__FreeBSD__) || defined (__APPLE__) || defined (__OpenBSD__) || defined (__NetBSD__)

int net_getmac(const char *ifname, char *macaddr) {

  struct ifaddrs *ifap, *ifa;
  struct sockaddr_dl *sdl;

  if (getifaddrs(&ifap)) {
    log_err(errno, "getifaddrs() failed!");
    return -1;
  }

  ifa = ifap;
  while (ifa) {
    if ((strcmp(ifa->ifa_name, ifname) == 0) &&
	(ifa->ifa_addr->sa_family == AF_LINK)) {
      sdl = (struct sockaddr_dl *)ifa->ifa_addr;
      switch(sdl->sdl_type) {
      case IFT_ETHER:
#ifdef IFT_IEEE80211
      case IFT_IEEE80211:
#endif
	break;
      default:
	continue;
      }
      if (sdl->sdl_alen != PKT_ETH_ALEN) {
	log_err(errno, "Wrong sdl_alen!");
	freeifaddrs(ifap);
	return -1;
      }
      memcpy(macaddr, LLADDR(sdl), PKT_ETH_ALEN);
      freeifaddrs(ifap);
      return 0;
    }
    ifa = ifa->ifa_next;
  }  
  freeifaddrs(ifap);
  return -1;
}

/**
 * Opens an Ethernet interface. As an option the interface can be set in
 * promisc mode. If not null macaddr and ifindex are filled with the
 * interface mac address and index
 **/

/* Relevant IOCTLs
FIONREAD Get the number of bytes in input buffer
SIOCGIFADDR Get interface address (IP)
BIOCGBLEN, BIOCSBLEN Get and set required buffer length
BIOCGDLT Type of underlying data interface
BIOCPROMISC Set in promisc mode
BIOCFLUSH Flushes the buffer of incoming packets
BIOCGETIF, BIOCSETIF Set hardware interface. Uses ift_name
BIOCSRTIMEOUT, BIOCGRTIMEOUT Set and get timeout for reads
BIOCGSTATS Return stats for the interface
BIOCIMMEDIATE Return immediately from reads as soon as packet arrives.
BIOCSETF Set filter
BIOCVERSION Return the version of BPF
BIOCSHDRCMPLT BIOCGHDRCMPLT Set flag of wheather to fill in MAC address
BIOCSSEESENT BIOCGSEESENT Return locally generated packets */

int net_open_eth(net_interface *netif) {
  char devname[IFNAMSIZ+5]; /* "/dev/" + ifname */
  int devnum;
  struct ifreq ifr;
  struct ifaliasreq areq;
  int local_fd;
  struct bpf_version bv;

  u_int32_t ipaddr;
  struct sockaddr_dl hwaddr;
  unsigned int value;

  /* Find suitable device */
  for (devnum = 0; devnum < 255; devnum++) { /* TODO 255 */ 
    snprintf(devname, sizeof(devname), "/dev/bpf%d", devnum);
    devname[sizeof(devname)] = 0;
    if ((netif->fd = open(devname, O_RDWR)) >= 0) break;
    if (errno != EBUSY) break;
  } 
  if (netif->fd < 0) {
    log_err(errno, "Can't find bpf device");
    return -1;
  }

  /* Set the interface */
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, netif->devname, sizeof(ifr.ifr_name));
  if (ioctl(netif->fd, BIOCSETIF, &ifr) < 0) {
    log_err(errno,"ioctl() failed");
    return -1;
  }

  /* Get and validate BPF version */
  if (ioctl(netif->fd, BIOCVERSION, &bv) < 0) {
    log_err(errno,"ioctl() failed!");
    return -1;
  }  
  if (bv.bv_major != BPF_MAJOR_VERSION ||
      bv.bv_minor < BPF_MINOR_VERSION) {
    log_err(errno,"wrong BPF version!");
    return -1;
  }

  /* Get the MAC address of our interface */
  if (net_getmac(netif->devname, netif->hwaddr)) {
    log_err(0,"Did not find MAC address!");
  }
  else {
    netif->flags |= NET_ETHHDR;
  }
  
  if (netif->hwaddr[0] & 0x01) {
    log_err(0, "Ethernet has broadcast or multicast address: %.16s", netif->devname);
    return -1;
  }

  /* Set interface in promisc mode */
  if (netif->flags & NET_PROMISC) {
    value = 1;
    if (ioctl(netif->fd, BIOCPROMISC, NULL) < 0) {
      log_err(errno,"ioctl() failed!");
      return -1;
    }  
    value = 1;
    if (ioctl(netif->fd, BIOCSHDRCMPLT, &value) < 0) {
      log_err(errno,"ioctl() failed!");
      return -1;
    }  
  }
  else {
    value = 0;
    if (ioctl(netif->fd, BIOCSHDRCMPLT, &value) < 0) {
      log_err(errno,"ioctl() failed!");
      return -1;
    }  
  }

  /* Make sure reads return as soon as packet has been received */
  value = 1;
  if (ioctl(netif->fd, BIOCIMMEDIATE, &value) < 0) {
    log_err(errno,"ioctl() failed!");
    return -1;
  }  

  return 0;
}

#endif

