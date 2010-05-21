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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>

#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#define inaddrr(x) (*(struct in_addr *) &ifr->x[sizeof sa.sin_port])
#define IFRSIZE   ((int)(size * sizeof (struct ifreq)))

int main(void)
{
  unsigned char      *u;
  int                sockfd, size  = 1;
  struct ifreq       *ifr;
  struct ifconf      ifc;
  struct sockaddr_in sa;

  if (0 > (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP))) {
   fprintf(stderr, "Cannot open socket.\n");
    exit(EXIT_FAILURE);
  }

  ifc.ifc_len = IFRSIZE;
  ifc.ifc_req = NULL;

  do {
    ++size;
    /* realloc buffer size until no overflow occurs  */
    if (NULL == (ifc.ifc_req = realloc(ifc.ifc_req, IFRSIZE))) {
      fprintf(stderr, "Out of memory.\n");
      exit(EXIT_FAILURE);
    }
    ifc.ifc_len = IFRSIZE;
    if (ioctl(sockfd, SIOCGIFCONF, &ifc)) {
      perror("ioctl SIOCFIFCONF");
      exit(EXIT_FAILURE);
    }
  } while  (IFRSIZE <= ifc.ifc_len);

  ifr = ifc.ifc_req;
  for (;(char *) ifr < (char *) ifc.ifc_req + ifc.ifc_len; ++ifr) {

    if (ifr->ifr_addr.sa_data == (ifr+1)->ifr_addr.sa_data) {
      continue;  /* duplicate, skip it */
    }

    if (ioctl(sockfd, SIOCGIFFLAGS, ifr)) {
      continue;  /* failed to get flags, skip it */
    }

    printf("Interface:  %s\n", ifr->ifr_name);
    printf("IP Address: %s\n", inet_ntoa(inaddrr(ifr_addr.sa_data)));

    /*
      This won't work on HP-UX 10.20 as there's no SIOCGIFHWADDR ioctl. You'll
      need to use DLPI or the NETSTAT ioctl on /dev/lan0, etc (and you'll need
      to be root to use the NETSTAT ioctl. Also this is deprecated and doesn't
      work on 11.00).

      On Digital Unix you can use the SIOCRPHYSADDR ioctl according to an old
      utility I have. Also on SGI I think you need to use a raw socket, e.g. s
      = socket(PF_RAW, SOCK_RAW, RAWPROTO_SNOOP)

      Dave

      From: David Peter <dave.peter@eu.citrix.com>
     */

    if (0 == ioctl(sockfd, SIOCGIFHWADDR, ifr)) {

      /* Select which  hardware types to process.
       *
       *    See list in system include file included from
       *    /usr/include/net/if_arp.h  (For example, on
       *    Linux see file /usr/include/linux/if_arp.h to
       *    get the list.)
       */
      switch (ifr->ifr_hwaddr.sa_family) {
      default:
	printf("\n");
	continue;
      case  ARPHRD_NETROM:  case  ARPHRD_ETHER:  case  ARPHRD_PPP:
      case  ARPHRD_EETHER:  case  ARPHRD_IEEE802: break;
      }

      u = (unsigned char *) &ifr->ifr_addr.sa_data;

      if (u[0] + u[1] + u[2] + u[3] + u[4] + u[5]) {
        printf("HW Address: %2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2x\n",
	       u[0], u[1], u[2], u[3], u[4], u[5]);
      }
    }
    
    if (0 == ioctl(sockfd, SIOCGIFNETMASK, ifr) &&
	strcmp("255.255.255.255", inet_ntoa(inaddrr(ifr_addr.sa_data)))) {
      printf("Netmask:    %s\n", inet_ntoa(inaddrr(ifr_addr.sa_data)));
    }
    
    if (ifr->ifr_flags & IFF_BROADCAST) {
      if (0 == ioctl(sockfd, SIOCGIFBRDADDR, ifr) &&
	  strcmp("0.0.0.0", inet_ntoa(inaddrr(ifr_addr.sa_data)))) {
        printf("Broadcast:  %s\n", inet_ntoa(inaddrr(ifr_addr.sa_data)));
      }
    }
    
    if (0 == ioctl(sockfd, SIOCGIFMTU, ifr)) {
      printf("MTU:        %u\n",  ifr->ifr_mtu);
    }
    
    if (0 == ioctl(sockfd, SIOCGIFMETRIC, ifr)) {
      printf("Metric:     %u\n",  ifr->ifr_metric);
    } printf("\n");
  }
  
  close(sockfd);
  return EXIT_SUCCESS;
}
