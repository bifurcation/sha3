#ifndef _SHA2_H_
#define _SHA2_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define PRUint8 uint8_t
#define PRUint32 uint32_t
#define SHA256_LENGTH 32
#define SHA512_LENGTH 64
#define SECStatus int
#define SECSuccess 0
#define PRUint64 uint64_t
#define PRBool int
#define PR_BYTES_PER_LONG 8
#define HAVE_LONG_LONG
#define SHA256_BLOCK_LENGTH 64
#define SHA512_BLOCK_LENGTH 128
#define PORT_New(x) malloc(sizeof(x))
#define PORT_Free(x) free(x)
#define PORT_Memcpy(dst, src, n) memcpy(dst, src, n)
#define PORT_Strlen(str) strlen(str)
#define LL_SHL(r, a, b)     ((r) = (uint64_t)(a) << (b))
#define PR_MIN(x, y)  ((x < y)? x : y)

struct SHA256ContextStr;
struct SHA512ContextStr;
typedef struct SHA256ContextStr SHA256Context;
typedef struct SHA512ContextStr SHA512Context;

extern SHA256Context *SHA256_NewContext(void);
extern void SHA256_DestroyContext(SHA256Context *cx, PRBool freeit);
extern void SHA256_Begin(SHA256Context *cx);
extern void SHA256_Update(SHA256Context *cx, const unsigned char *input,
                        unsigned int inputLen);
extern void SHA256_End(SHA256Context *cx, unsigned char *digest,
                     unsigned int *digestLen, unsigned int maxDigestLen);

extern SHA512Context *SHA512_NewContext(void);
extern void SHA512_DestroyContext(SHA512Context *cx, PRBool freeit);
extern void SHA512_Begin(SHA512Context *cx);
extern void SHA512_Update(SHA512Context *cx, const unsigned char *input,
                        unsigned int inputLen);
extern void SHA512_End(SHA512Context *cx, unsigned char *digest,
                     unsigned int *digestLen, unsigned int maxDigestLen);

#endif /* ndef _SHA2_H_ */
