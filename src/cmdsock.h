#ifndef CMDSOCK
#define CMDSOCK

#define  CMDSOCK_LIST           0
#define  CMDSOCK_DHCP_LIST      1
#define  CMDSOCK_DHCP_RELEASE   2

struct cmdsock_query { 
  int type;
  union {
    unsigned char mac[DHCP_ETH_ALEN];
  } data;
}  __attribute__((packed));

typedef struct cmdsock_query CMDSOCK_QUERY;

#endif /* CMDSOCK */
