#ifndef CMDSOCK
#define CMDSOCK

#define  CMDSOCK_DHCP_LIST      0
#define  CMDSOCK_DHCP_RELEASE   1
#define  CMDSOCK_LIST           2
#define  CMDSOCK_SHOW           3
#define  CMDSOCK_AUTHORIZE      4
#define  CMDSOCK_DHCP_DROP      5
#define  CMDSOCK_ROUTE          6
#define  CMDSOCK_ROUTE_SET      7
#define  CMDSOCK_ENTRY_FOR_IP   8
#define  CMDSOCK_ENTRY_FOR_MAC  9
#define  CMDSOCK_RELOAD        10
#define  CMDSOCK_OPT_JSON      (1)

#include "pkt.h"
#include "session.h"

struct cmdsock_request { 
  uint16_t type;
  uint16_t options;
  union {
    unsigned char mac[PKT_ETH_ALEN];
    struct cmdsock_session {
      struct in_addr ip;
      char username[256];
      char sessionid[17];
      struct session_params params;
    } sess;
  } data;
}  __attribute__((packed));

typedef struct cmdsock_request CMDSOCK_REQUEST;

#endif /* CMDSOCK */
