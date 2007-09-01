#ifndef CMDSOCK
#define CMDSOCK

#define  CMDSOCK_DHCP_LIST      0
#define  CMDSOCK_DHCP_RELEASE   1
#define  CMDSOCK_LIST           2
#define  CMDSOCK_SHOW           3
#define  CMDSOCK_AUTHORIZE      4

#include "session.h"

struct cmdsock_request { 
  unsigned char type;
  union {
    unsigned char mac[DHCP_ETH_ALEN];
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
