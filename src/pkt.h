/* 
 * Packet Headers
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (c) 2007 David Bird <david@coova.com>
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 * The initial developer of the original code is
 * Jens Jakobsen <jj@chillispot.org>
 *
 */


#ifndef _PKT_H
#define _PKT_H

#define PKT_ETH_ALEN              6 /* Ethernet Address Length */
#define PKT_ETH_HLEN             14 /* Ethernet Header Length */

#define PKT_ETH_PROTO_IP     0x0800
#define PKT_ETH_PROTO_ARP    0x0806
#define PKT_ETH_PROTO_EAPOL  0x888e

#define PKT_IP_PLEN            1500 /* IP Payload Length */
#define PKT_IP_VER_HLEN        0x45 
#define PKT_IP_ALEN               4
#define PKT_IP_HLEN              20

#define PKT_IP_PROTO_ICMP         1 /* ICMP Protocol number */
#define PKT_IP_PROTO_TCP          6 /* TCP Protocol number */
#define PKT_IP_PROTO_UDP         17 /* UDP Protocol number */
#define PKT_IP_PROTO_GRE         47 /* GRE Protocol number */

#define PKT_UDP_HLEN              8

#define PKT_EAP_PLEN           1500 /* Dot1x Payload length */

#define DHCP_TAG_VLEN           255 /* Tag value always shorter than this */
#define EAPOL_TAG_VLEN          255 /* Tag value always shorter than this */

#define DHCP_HTYPE_ETH            1
#define DHCP_CHADDR_LEN          16 /* Length of client hardware address */
#define DHCP_SNAME_LEN           64 /* Length of server host name */
#define DHCP_FILE_LEN           128 /* Length of boot file name*/
#define DHCP_OPTIONS_LEN        312 /* Length of optional parameters field */
#define DHCP_MIN_LEN   28+16+64+128 /* Length of packet excluding options */
#define DHCP_LEN  DHCP_MIN_LEN + DHCP_OPTIONS_LEN

struct pkt_ethhdr_t {
  uint8_t  dst[PKT_ETH_ALEN];
  uint8_t  src[PKT_ETH_ALEN];
  uint16_t prot;
} __attribute__((packed));



struct pkt_iphdr_t {
  uint8_t  version_ihl;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
} __attribute__((packed));


struct pkt_ipphdr_t {
  /* Convenience structure:
     Same as pkt_iphdr_t, but also
     with ports (UDP and TCP packets) */
  uint8_t  version_ihl;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
} __attribute__((packed));


struct pkt_ippacket_t {
  struct pkt_ethhdr_t ethh;
  struct pkt_iphdr_t  iph;
  uint8_t payload[PKT_IP_PLEN];
} __attribute__((packed));

/*
  0      7 8     15 16    23 24    31  
  +--------+--------+--------+--------+ 
  |     Source      |   Destination   | 
  |      Port       |      Port       | 
  +--------+--------+--------+--------+ 
  |                 |                 | 
  |     Length      |    Checksum     | 
  +--------+--------+--------+--------+ 
  |                                     
  |          data octets ...            
  +---------------- ...                 
  
  User Datagram Header Format
*/

struct pkt_udphdr_t {
  uint16_t src;
  uint16_t dst;
  uint16_t len;
  uint16_t check;
} __attribute__((packed));

/*
  TCP Header Format

    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct pkt_tcphdr_t {
  uint16_t src;
  uint16_t dst;
  uint32_t seq;
  uint32_t ack;
  uint16_t flags;
  uint16_t win;
  uint16_t check;
  uint16_t urgent;
  uint32_t options;
} __attribute__((packed));


/*
  0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+
*/

struct dhcp_packet_t { /* From RFC 2131 */
  uint8_t op;       /* 1 Message op code / message type.  1 = BOOTREQUEST, 2 = BOOTREPLY */
  uint8_t htype;    /* 1 Hardware address type, see ARP section
			  in "Assigned Numbers" RFC; e.g., '1' =
			  10mb ethernet.*/
  uint8_t hlen;     /* 1 Hardware address length (e.g.  '6' for
			  10mb ethernet).*/
  uint8_t hops;     /* 1 Client sets to zero, optionally used
			  by relay agents when booting via a
			  relay agent.*/
  uint32_t xid;    /* 4 Transaction ID, a random number chosen
			  by the client, used by the client and
			  server to associate messages and
			  responses between a client and a
			  server.*/
  uint16_t secs;   /* 2 Filled in by client, seconds elapsed since
			  client began address acquisition or renewal
			  process.*/
  uint8_t flags[2];  /* 2  Flags (see figure 2).*/
  uint32_t ciaddr; /* 4 Client IP address; only filled in if
			  client is in BOUND, RENEW or REBINDING state
			  and can respond to ARP requests.*/
  uint32_t yiaddr; /* 4 'your' (client) IP address.*/
  uint32_t siaddr; /* 4 IP address of next server to use in
			  bootstrap; returned in DHCPOFFER,
			  DHCPACK by server.*/
  uint32_t giaddr; /* 4 Relay agent IP address, used in booting via a relay agent.*/
  uint8_t  chaddr[DHCP_CHADDR_LEN]; /* 16 Client hardware address.*/
  uint8_t sname[DHCP_SNAME_LEN]; /* 64 Optional server host name,
			  null terminated string.*/
  uint8_t file[DHCP_FILE_LEN]; /* 128 Boot file name, null terminated
                          string; "generic" name or null in
                          DHCPDISCOVER, fully qualified directory-path
                          name in DHCPOFFER.*/
  uint8_t options[DHCP_OPTIONS_LEN]; /* var Optional parameters
                          field.  See the options documents for a list
                          of defined options.*/
} __attribute__((packed));


struct dhcp_fullpacket_t {
  struct pkt_ethhdr_t  ethh;
  struct pkt_iphdr_t   iph;
  struct pkt_udphdr_t  udph;
  struct dhcp_packet_t dhcp;
} __attribute__((packed));


struct dhcp_tag_t {
  uint8_t t;
  uint8_t l;
  uint8_t v[DHCP_TAG_VLEN];
} __attribute__((packed));


struct arp_packet_t { /* From RFC 826 */
  uint16_t hrd; /* 16.bit: (ar$hrd) Hardware address space (e.g.,
		    Ethernet, Packet Radio Net.) */
  uint16_t pro; /* 16.bit: (ar$pro) Protocol address space.  For
		    Ethernet hardware, this is from the set of type
		    fields ether_typ$<protocol>. */
  uint8_t hln;  /* 8.bit: (ar$hln) byte length of each hardware address */
  uint8_t pln;  /* 8.bit: (ar$pln) byte length of each protocol address */
  uint16_t op;  /* 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY) */
  uint8_t sha[PKT_ETH_ALEN]; /* nbytes: (ar$sha) Hardware address of
		    sender of this packet, n from the ar$hln field. */
  uint8_t spa[PKT_IP_ALEN];  /* mbytes: (ar$spa) Protocol address of
		    sender of this packet, m from the ar$pln field. */
  uint8_t tha[PKT_ETH_ALEN]; /* nbytes: (ar$tha) Hardware address of
		  target of this packet (if known). */
  uint8_t tpa[PKT_IP_ALEN]; /* mbytes: (ar$tpa) Protocol address of
				 target.*/
} __attribute__((packed));


struct arp_fullpacket_t {
  struct pkt_ethhdr_t ethh;
  struct arp_packet_t arp;
} __attribute__((packed));


struct dns_packet_t { /* From RFC 1035 */
  uint16_t id;      /* 16 bit: Generated by requester. Copied in reply */
  uint16_t flags;   /* 16 bit: Flags */
  uint16_t qdcount; /* 16 bit: Number of questions */
  uint16_t ancount; /* 16 bit: Number of answer records */
  uint16_t nscount; /* 16 bit: Number of name servers */
  uint16_t arcount; /* 16 bit: Number of additional records */
  uint8_t  records[PKT_IP_PLEN];
} __attribute__((packed));


struct dns_fullpacket_t {
  struct pkt_ethhdr_t ethh;
  struct pkt_iphdr_t iph;
  struct pkt_udphdr_t udph;
  struct dns_packet_t dns;
} __attribute__((packed));


struct pkt_dot1xhdr_t {
  uint8_t  ver;
  uint8_t  type;
  uint16_t len;
} __attribute__((packed));


struct eap_packet_t {
  uint8_t  code;
  uint8_t  id;
  uint16_t length;
  uint8_t  type;
  uint8_t  payload[PKT_EAP_PLEN];
} __attribute__((packed));


struct dot1xpacket_t {
  struct pkt_ethhdr_t   ethh;
  struct pkt_dot1xhdr_t dot1x;
  struct eap_packet_t   eap;
} __attribute__((packed));


struct eapol_tag_t {
  uint8_t t;
  uint8_t l;
  uint8_t v[EAPOL_TAG_VLEN];
} __attribute__((packed));


#endif
