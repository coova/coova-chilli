#ifndef CMDSOCK
#define CMDSOCK

#define  CMDSOCK_LIST           0
#define  CMDSOCK_DHCP_LIST      1
#define  CMDSOCK_DHCP_RELEASE   2
#define  CMDSOCK_AUTHORIZE      3

struct cmdsock_request { 
  int type;
  union {
    unsigned char mac[DHCP_ETH_ALEN];
    struct session_params params;
  } data;
}  __attribute__((packed));

typedef struct cmdsock_request CMDSOCK_REQUEST;

#endif /* CMDSOCK */
