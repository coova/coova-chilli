#ifndef CMDSOCK
#define CMDSOCK

#define  CMDSOCK_DHCP_LIST      0
#define  CMDSOCK_DHCP_RELEASE   1
#define  CMDSOCK_LIST           2
#define  CMDSOCK_SHOW           3
#define  CMDSOCK_AUTHORIZE      4
#define  CMDSOCK_OPT_JSON      (1)

#include "pkt.h"
#include "session.h"

struct cmdsock_request { 
  unsigned char type;
  unsigned char options;
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
