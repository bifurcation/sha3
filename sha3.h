#ifndef _SHA3_H_
#define _SHA3_H_

#include <stdlib.h>
#include <stdint.h>

/* This should ultimately become part of blapi.h */
typedef enum { PR_FALSE, PR_TRUE } PRBool;
typedef struct SHA3ContextStr SHA3Context;

/*
 *  Most of the SHA3 functions are identical, so just have one function and
 *  Alias them
 */
#define SHA3_224_NewContext SHA3_NewContext
#define SHA3_224_DestroyContext SHA3_DestroyContext
#define SHA3_224_Begin SHA3_Begin
#define SHA3_224_EndRaw SHA3_224_End
#define SHA3_224_FlattenSize SHA3_FlattenSize
#define SHA3_224_Flatten SHA3_Flatten
#define SHA3_224_Resurrect SHA3_Resurrect

#define SHA3_256_NewContext SHA3_NewContext
#define SHA3_256_DestroyContext SHA3_DestroyContext
#define SHA3_256_Begin SHA3_Begin
#define SHA3_256_EndRaw SHA3_256_End
#define SHA3_256_FlattenSize SHA3_FlattenSize
#define SHA3_256_Flatten SHA3_Flatten
#define SHA3_256_Resurrect SHA3_Resurrect

#define SHA3_384_NewContext SHA3_NewContext
#define SHA3_384_DestroyContext SHA3_DestroyContext
#define SHA3_384_Begin SHA3_Begin
#define SHA3_384_EndRaw SHA3_384_End
#define SHA3_384_FlattenSize SHA3_FlattenSize
#define SHA3_384_Flatten SHA3_Flatten
#define SHA3_384_Resurrect SHA3_Resurrect

#define SHA3_512_NewContext SHA3_NewContext
#define SHA3_512_DestroyContext SHA3_DestroyContext
#define SHA3_512_Begin SHA3_Begin
#define SHA3_512_EndRaw SHA3_512_End
#define SHA3_512_FlattenSize SHA3_FlattenSize
#define SHA3_512_Flatten SHA3_Flatten
#define SHA3_512_Resurrect SHA3_Resurrect

extern SHA3Context *SHA3_NewContext(void);
extern void SHA3_DestroyContext(SHA3Context *cx, PRBool freeit);
extern void SHA3_Begin(SHA3Context *cx);
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
