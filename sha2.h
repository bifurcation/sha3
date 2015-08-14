#ifndef _SHA2_H_
#define _SHA2_H_

#include "prtypes.h"
// Relevant parts of blapi.h and blapit.h
struct SHA256ContextStr {
    union {
	PRUint32 w[64];	    /* message schedule, input buffer, plus 48 words */
	PRUint8  b[256];
    } u;
    PRUint32 h[8];		/* 8 state variables */
    PRUint32 sizeHi,sizeLo;	/* 64-bit count of hashed bytes. */
};

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
