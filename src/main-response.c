/* 
 *
 * Copyright (C) 2003, 2004, 2005 Mondru AB.
 * Copyright (c) 2006-2007 David Bird <david@coova.com>
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
  fprintf(stderr, "       %s -nt <challenge> <uamsecret> <username> <password>\n", program);
  return 1;
}

static int hextochar(char *src, unsigned char * dst, int len) {
  char x[3];
  int n;
  int y;

  for (n=0; n < len; n++) {
    x[0] = src[n*2+0];
    x[1] = src[n*2+1];
    x[2] = 0;

    if (sscanf(x, "%2x", &y) != 1)
      return -1;

    dst[n] = (unsigned char) y;
  }

  return 0;
}

static int chartohex(unsigned char *src, char *dst, int len) {
  char x[3];
  int n;
  
  for (n=0; n < len; n++) {
    snprintf(x, 3, "%.2x", src[n]);
    dst[n*2+0] = x[0];
    dst[n*2+1] = x[1];
  }
  dst[len*2] = 0;
  return 0;
}

int main(int argc, char **argv) {
  unsigned char chap_ident = 0;
  unsigned char challenge[32];
  unsigned char response[32];
  char buffer[128];
  MD5_CTX context;

  int idx = 0;
  int usent = 0;

  if (argc < 2)
    return usage(argv[0]);

  if (!strcmp(argv[1],"-nt")) {
    usent = 1;
    argc--;
    idx++;
  }

  if (argc < 4)
    return usage(argv[0]);

  if (argc == 5) 
    chap_ident = atoi(argv[idx+4]);

  /* challeng - argv 1 */
  memset(buffer, 0, sizeof(buffer));
  strcpy(buffer, argv[idx+1]);
  hextochar(buffer, challenge, MD5LEN);

  /* uamsecret - argv 2 */
  MD5Init(&context);
  MD5Update(&context, challenge, MD5LEN);
  MD5Update(&context, (uint8_t*)argv[idx+2], strlen(argv[idx+2]));
  MD5Final(challenge, &context);

  if (usent) {

#ifdef HAVE_OPENSSL
    uint8_t ntresponse[24];

    if (argc < 5)
      return usage(argv[0]);

    GenerateNTResponse(challenge, challenge,
		       (uint8_t*)argv[idx+3], strlen(argv[idx+3]),
		       (uint8_t*)argv[idx+4], strlen(argv[idx+4]),
		       ntresponse);
    chartohex(ntresponse, buffer, 24);
    printf("%s\n", buffer);

#else

    printf("Requires OpenSSL Support\n");

#endif

  } else {

    /* password - argv 3 */
    MD5Init(&context);
    MD5Update(&context, (uint8_t*)&chap_ident, 1);	  
    MD5Update(&context, (uint8_t*)argv[idx+3], strlen(argv[idx+3]));
    MD5Update(&context, challenge, MD5LEN);
    MD5Final(response, &context);
    
    chartohex(response, buffer, MD5LEN);
    printf("%s\n", buffer);
  }

  return 0;
}
