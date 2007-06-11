/* 
 *
 * Copyright (c) 2006 Coova Technologies Ltd
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 *
 * The contents of this file may be used under the terms of the GNU
 * General Public License Version 2, provided that the above copyright
 * notice and this permission notice is included in all copies or
 * substantial portions of the software.
 * 
 */

#include "system.h"
#include "md5.h"
#define MD5LEN 16

static int usage(char *program) {
  fprintf(stderr, "Usage: %s <challenge> <uamsecret> <password>\n", program);
  return 1;
}

static int hextochar(char *src, unsigned char * dst) {
  char x[3];
  int n;
  int y;

  for (n=0; n < MD5LEN; n++) {
    x[0] = src[n*2+0];
    x[1] = src[n*2+1];
    x[2] = 0;

    if (sscanf(x, "%2x", &y) != 1)
      return -1;

    dst[n] = (unsigned char) y;
  }

  return 0;
}

static int chartohex(unsigned char *src, char *dst) {
  char x[3];
  int n;
  
  for (n=0; n < MD5LEN; n++) {
    snprintf(x, 3, "%.2x", src[n]);
    dst[n*2+0] = x[0];
    dst[n*2+1] = x[1];
  }
  dst[MD5LEN*2] = 0;
  return 0;
}

int main(int argc, char **argv) {
  unsigned char challenge[MD5LEN];
  unsigned char response[MD5LEN];
  char buffer[MD5LEN*3];
  MD5_CTX context;

  if (argc != 4) return usage(argv[0]);

  /* challeng - argv 1 */
  memset(buffer, 0, sizeof(buffer));
  /*fprintf(stderr,"challenge: %s\n",argv[1]);*/
  strcpy(buffer, argv[1]);
  hextochar(buffer, challenge);

  MD5Init(&context);
  MD5Update(&context, challenge, MD5LEN);
  /* uamsecret - argv 2 */
  /*fprintf(stderr,"uamsecret: %s\n",argv[2]);*/
  MD5Update(&context, (uint8_t*)argv[2], strlen(argv[2]));
  MD5Final(challenge, &context);

  MD5Init(&context);
  MD5Update(&context, (uint8_t*)"\0", 1);	  
  /* password - argv 3 */
  /*fprintf(stderr,"password: %s\n",argv[3]);*/
  MD5Update(&context, (uint8_t*)argv[3], strlen(argv[3]));
  MD5Update(&context, challenge, MD5LEN);
  MD5Final(response, &context);

  chartohex(response, buffer);
  printf("%s\n", buffer);
  return 0;
}
