#ifndef _SHA3_H_
#define _SHA3_H_

#include <stdlib.h>
#include <stdint.h>

// Bogus NSPR
typedef int PRBool;
#define PORT_New(x) malloc(sizeof(x))
#define PORT_Free(x) free(x)
#define PR_FALSE 0
#define PR_TRUE 1


/* This should ultimately be copied to blapit.h */

/* All of the SHA3 functions use a common context struct */
typedef struct SHA3ContextStr {
  /*
   *  Length of the expected output, in bytes
   *  SHA3-224 => 1152 bits = 144
   *  SHA3-256 => 1088 bits = 136
   *  SHA3-384 =>  832 bits = 104
   *  SHA3-512 =>  576 bits =  72
   *  SHAKE128 => as specified
   *  SHAKE256 => as specified
   */
  size_t d;

  /*
   *  Width of the sponge input function, in bytes
   *  SHA3-d   => 1600 - 16*d bits = 200 - 2*d bytes
   *  SHAKE128 => 1600 - 256
   *  SHAKE256 => 1600 - 512
   */
  size_t r;

  /*
   *  Context for usage
   *  Hash = 01
   *  XOF  = 1111
   */
  uint8_t domain;
  uint8_t domainLength;

  /* A buffer to hold pending input */
  uint8_t todo[200];
  uint8_t todoLength;

  /* Sponge state */
  uint64_t A[5][5];

  /* Temporary storage for in-place [chi] */
  uint64_t B[5][5];

  /* Temporary column sums [theta] */
  uint64_t C[5];

  /* Temporary per-column addends [theta] */
  uint64_t D[5];
} SHA3Context;

/* This should ultimately become part of blapi.h */

extern SHA3Context *SHA3_NewContext(void);
extern void SHA3_DestroyContext(SHA3Context *cx, PRBool freeit);
extern void SHA3_224_Begin(SHA3Context *cx);
extern void SHA3_256_Begin(SHA3Context *cx);
extern void SHA3_384_Begin(SHA3Context *cx);
extern void SHA3_512_Begin(SHA3Context *cx);
extern void SHA3_Update(SHA3Context *cx, const unsigned char *input,
                                          unsigned int inputLen);
extern void SHA3_End(SHA3Context *cx, unsigned char *digest,
                                 unsigned int *digestLen, unsigned int maxDigestLen);

/*
// TODO implement the below, with appropriate repetition to
//      account for the various hash sizes

extern SECStatus SHA256_HashBuf(unsigned char *dest, const unsigned char *src,
                                PRUint32 src_length);
extern SECStatus SHA256_Hash(unsigned char *dest, const char *src);
extern void SHA256_TraceState(SHA256Context *cx);
extern unsigned int SHA256_FlattenSize(SHA256Context *cx);
extern SECStatus SHA256_Flatten(SHA256Context *cx,unsigned char *space);
extern SHA256Context * SHA256_Resurrect(unsigned char *space, void *arg);
extern void SHA256_Clone(SHA256Context *dest, SHA256Context *src);
*/

#endif /* ndef _SHA3_H_ */
