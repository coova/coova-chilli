#ifndef MD5_H
#define MD5_H
#include "system.h"

#include <openssl/md5.h>

#if HAVE_OPENSSL

#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final

#else

struct MD5Context {
  uint32_t buf[4];
  uint32_t bits[2];
  unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf, size_t len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(uint32_t buf[4], uint32_t const in[16]);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct MD5Context MD5_CTX;
#endif 

#endif /* !MD5_H */
