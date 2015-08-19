/*#include "prtypes.h"	for PRUintXX */
/*#include "prlong.h" */

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include "sha3.h"
typedef uint64_t PRUint64;
typedef uint32_t PRUint32;
typedef enum { SECSuccess=0, SECFailure=-1 } SECStatus;
#define PORT_Assert(x)
#define PORT_New(x) (x *)malloc(sizeof(x))
#define PORT_Memset(x,y,z) memset(x,y,z)
#define PORT_Memcpy(x,y,z) memcpy(x,y,z)
#define PORT_Free(x) free(x)
#define PORT_Strlen(x) strlen(x)
#define SHA_MIN(x,y) (((x)>(y))?(y):(x))

#define X_SIZE 5
#define Y_SIZE 5



typedef struct SHA3ContextStr SHA3Context;

struct SHA3ContextStr {
    PRUint64 A1[X_SIZE*Y_SIZE];
    PRUint64 A2[X_SIZE*Y_SIZE];
    unsigned char buf[X_SIZE*Y_SIZE*sizeof(PRUint64)];
    unsigned int bufSize;
};


#if defined(_MSC_VER)
#pragma intrinsic (_rotl64, _rotr64)
#define ROTR(a,n) _rotr64(a,n)
#define ROTL(a,n) _rotl64(a,n)
#else
#define ROTL(a,n) (((a)<<(n))|((a)>>(64-n)))
#define ROTR(a,n) (((a)>>(n))|((a)<<(64-n)))
#endif

#if defined(_MSC_VER)
#pragma intrinsic(_byteswap_uint64)
#define SHA_HTONLL(x) _byteswap_uint64(x)

#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__x86_64))
static __inline__ uint64_t swap8b(uint64_t value)
{
    __asm__("bswapq %0" : "+r" (value));
    return (value);
}
#define SHA_HTONLL(x) swap8b(x)

#else
#define SHA_MASK16 ULLC(0000FFFF,0000FFFF)
#define SHA_MASK8  ULLC(00FF00FF,00FF00FF)
static PRUint64 swap8b(PRUint64 x)  {
  PRUint64 t1 = x;
  t1 = ((t1 & SHA_MASK8 ) <<  8) | ((t1 >>  8) & SHA_MASK8 );
  t1 = ((t1 & SHA_MASK16) << 16) | ((t1 >> 16) & SHA_MASK16);
  return (t1 >> 32) | (t1 << 32);
}
#define SHA_HTONLL swap8b
#endif
#define BYTESWAP8(x) x = SHA_HTONLL(x)

/* Select the x value to the left or right */
#define LEFT(x) ((x) == 0 ? (X_SIZE-1) : ((x)-1))
#define RIGHT(x) ((x) == X_SIZE-1 ? 0 : ((x)+1))
/* convert x,y into a linear index */
#define IN(x,y) ((y)*Y_SIZE+(x))

#ifdef TEST_TRACE
#define DUMP_LANES(label,A) dump_lanes(label,A)
#define DUMP_BYTES(label,A) dump_bytes(label,A)
#define DUMP_BUF(label,b,size) dump_buf(label,b,size)

static void
dump_lanes(char *label, const PRUint64 *a)
{
    int x,y;
    printf("%s: \n", label);
    for (y=0; y < Y_SIZE; y++) {
        for (x=0; x < X_SIZE; x++) {
                printf("<%d,%d> = 0x%016lx\n",x,y,a[IN(x,y)]);
        }
    }
}

static void
dump_bytes(char *label, const PRUint64 *a)
{
    int i,z;
    printf("%s:", label);
    for (i=0; i < X_SIZE*Y_SIZE; i++) {
        PRUint64 A = a[i];
        if ((i & 1) == 0) printf("\n");
        for (z=0; z < 8; z++) {
                printf("%02x ", (A >> (z*8)) & 0xff);
        }
    }
    printf("\n");
}

#else
#define DUMP_LANES(label,A)
#define DUMP_BYTES(label,A)
#define DUMP_BUF(label,b,size)
#endif

#if defined(TEST) || defined(TRACE)
void
dump_buf(char *label, const unsigned char *b, int size)
{
    int i,z;

    printf("%s:", label);
    for (i=0; i < size; i++) {
        if ((i % 16) == 0) {
           printf("\n");
        }
        printf("%02x ", b[i]);

    }
    printf("\n");
}
#endif

#define UNROLL5(x)  \
  x(0);             \
  x(1);             \
  x(2);             \
  x(3);             \
  x(4)

#define UNROLL25(x) \
  x(0);             \
  x(1);             \
  x(2);             \
  x(3);             \
  x(4);             \
  x(5);             \
  x(6);             \
  x(7);             \
  x(8);             \
  x(9);             \
  x(10);            \
  x(11);            \
  x(12);            \
  x(13);            \
  x(14);            \
  x(15);            \
  x(16);            \
  x(17);            \
  x(18);            \
  x(19);            \
  x(20);            \
  x(21);            \
  x(22);            \
  x(23);            \
  x(24)

/*
 * The z bits are stored in a single 64 bit word and all operations run
 * against that word, so a single assigment or operation operates on all
 * 64 bit of z at once. (z-x) mod w is a rotate operation.
 *
 * In the spec, all the functions take array A and return array A'. Many
 * Of the functions, however, can modify A in place, namely theta, rho, and
 * iota. The other two functions use the temparary A2 array. Since they are
 * called one after another, pi uses A2 as A' and chi uses A2 as A (putting
 * The result back into A1 where most functions expect it as an input.
 *
 * The spec specifies serveral elements that can be preprocessed into
 * Array indexes or shift values. We recalculate all those constants rather
 * than caclulate them on the fly.
 */

/*
 *  Theta input = A1, output=A1
 *
 * From section 3.2.1 FIPS-202: w=64 bits
 *
 *  For all (x,z) such that 0<=x<5 and 0<=z<w
 *     C[x,z] = A[x,0,z] ^ A[x,1,z] ^ A[x,2,z] ^ A[x,3,z] ^ A[x,4,z]
 *  For all (x,z) such that 0<=x<5 and 0<=z<w
 *     D[x,z] = C[(x-1) mod 5, z] ^ C[(x+1) mod 5, (z-1) mod w]
 *  For all (x,y,z) such that 0<=x<5 0<=y<5 and 0<=z<w
 *     A'[x,y,z] = A[x,y,z] ^ D[x,z]
 *
 */
static inline void
sha3_theta(SHA3Context *ctx)
{
    PRUint64 C[X_SIZE];
    PRUint64 D;
    PRUint64 *A = &ctx->A1[0];

#define STEP_THETA1(x)                          \
    C[x] = A[IN(x,0)] ^ A[IN(x,1)] ^ A[IN(x,2)] \
        ^ A[IN(x,3)] ^ A[IN(x,4)]

#define STEP_THETA2(x)                    \
    D = C[LEFT(x)] ^ ROTL(C[RIGHT(x)],1); \
    A[IN(x,0)] ^= D;                      \
    A[IN(x,1)] ^= D;                      \
    A[IN(x,2)] ^= D;                      \
    A[IN(x,3)] ^= D;                      \
    A[IN(x,4)] ^= D

    UNROLL5(STEP_THETA1);
    UNROLL5(STEP_THETA2);
}

/*
 *  Rho and Pi steps in one go
 *
 * From section 3.2.2 FIPS-202: w=64 bits
 *
 *  For all z such that 0<=z<w let A'[0,0,z]=A[0,0,z]
 *  Let (x,y) = (1,0)
 *  For t from 0 to 23:
 *     a. for all z such that 0<=z<w let A'[x,y,z]=A[x,y,9z-(t+1)(t+2)/2) mod w]
 *     b. let (x,y)=(y,(2*x+3*y) mod 5)
 *
 * Table 2: effective offsets (reordered)
 *
 *     x=0 x=1 x=2 x=3 x=4
 * y=0   0   1 190  28  91
 * y=1  36 300   6  55 276
 * y=2   3  10 171 153 231
 * y=3 105  45  15  21 136
 * y=4 210  66 253 120  78
 *
 * These are all mod w (=64) in the table below
 *
 * Note here, we are precalculationg everything and change this to 24 rotate
 * operations, rather than the hunt an peck style of the original.
 */

#define RHO(x) RHO_ ## x
#define RHO_0 64
#define RHO_1 1
#define RHO_2 62
#define RHO_3 28
#define RHO_4 27
#define RHO_5 36
#define RHO_6 44
#define RHO_7 6
#define RHO_8 55
#define RHO_9 20
#define RHO_10 3
#define RHO_11 10
#define RHO_12 43
#define RHO_13 25
#define RHO_14 39
#define RHO_15 41
#define RHO_16 45
#define RHO_17 15
#define RHO_18 21
#define RHO_19 8
#define RHO_20 18
#define RHO_21 2
#define RHO_22 61
#define RHO_23 56
#define RHO_24 14

/*
 * For the Pi phase, we invert the calculation so that the output of the rho
 * phase is written directly to the output in the locations dicated by the Pi
 * phase.
 *
 * From section 3.2.3 FIPS-202: w=64 bits
 *
 *  For all (x,y,z) such that 0<=x<5 0<=y<5 and 0<=z<w
 *      A'[x,y,z] = A[(x+3*y) mod 5, x, z]
 *
 * pi x/y transform precalculated
 *      x=0   x=1   x=2   x=3   x=4
 * y=0 (0,0) (1,1) (2,2) (3,3) (4,4)
 * y=1 (3,0) (4,1) (0,2) (1,3) (2,4)
 * y=2 (1,0) (2,1) (3,2) (4,3) (0,4)
 * y=3 (4,0) (0,1) (1,2) (2,3) (3,4)
 * y=4 (2,0) (3,1) (4,2) (0,3) (1,4)
 *
 * pi x/y inverse transform precalculated
 *      x=0   x=1   x=2   x=3   x=4
 * y=0 (0,0) (0,2) (0,4) (0,1) (0,3)
 * y=1 (1,3) (1,0) (1,2) (1,4) (1,1)
 * y=2 (2,1) (2,3) (2,0) (2,2) (2,4)
 * y=3 (3,4) (3,1) (3,3) (3,0) (3,2)
 * y=4 (4,2) (4,4) (4,1) (4,3) (4,0)
 */

#define PI_INV(x) PI_INV_ ## x
#define PI_INV_0 0
#define PI_INV_1 10
#define PI_INV_2 20
#define PI_INV_3 5
#define PI_INV_4 15
#define PI_INV_5 16
#define PI_INV_6 1
#define PI_INV_7 11
#define PI_INV_8 21
#define PI_INV_9 6
#define PI_INV_10 7
#define PI_INV_11 17
#define PI_INV_12 2
#define PI_INV_13 12
#define PI_INV_14 22
#define PI_INV_15 23
#define PI_INV_16 8
#define PI_INV_17 18
#define PI_INV_18 3
#define PI_INV_19 13
#define PI_INV_20 14
#define PI_INV_21 24
#define PI_INV_22 9
#define PI_INV_23 19
#define PI_INV_24 4

static inline void
sha3_rho_pi(SHA3Context *ctx)
{
    PRUint64 *A = &ctx->A1[0];
    PRUint64 *A_prime = &ctx->A2[0];

#define STEP_RHO_PI(i) \
    A_prime[PI_INV(i)] = ROTL(A[i],RHO(i))

    UNROLL25(STEP_RHO_PI);
}

/*
 *  Chi input = A2, output=A1
 *
 * From section 3.2.4 FIPS-202: w=64 bits
 *
 *  For all (x,y,z) such that 0<=x<5 0<=y<5 and 0<=z<w
 *      A'[x,y,z] = A[x,y,z] ^ (A[(x+1) mod 5,y,z] ^ 1) * A[(x+2) mod 5,y,z)]
 *
 * chi_right x/y transform precalculated
 *      x=0   x=1   x=2   x=3   x=4
 * y=0 (1,0) (2,0) (3,0) (4,0) (0,0)
 * y=1 (1,1) (2,1) (3,1) (4,1) (0,1)
 * y=2 (1,2) (2,2) (3,2) (4,2) (0,2)
 * y=3 (1,3) (2,3) (3,3) (4,3) (0,3)
 * y=4 (1,4) (2,4) (3,4) (4,4) (0,4)
 *
 */


static inline void
sha3_chi(SHA3Context *ctx)
{
    PRUint64 *A = &ctx->A2[0];
    PRUint64 *A_prime = &ctx->A1[0];
#define CHIR(x,i) (x / X_SIZE) * X_SIZE + ((x + i) % X_SIZE)
#define CHIR1(x) CHIR(x,1)
#define CHIR2(x) CHIR(x,2)
#define STEP_CHI(x) \
    A_prime[x] = A[x] ^ (~A[CHIR1(x)] & A[CHIR2(x)])

    UNROLL25(STEP_CHI);
}

/*
 *  Iota input = A1, output=A1
 *
 * From section 3.2.5 FIPS-202: w=64 bits
 *
 *  For all (x,y,z) such that 0<=x<5 0<=y<5 and 0<=z<w  A'[x,y,z]=A[x,y,z]
 *  Let RC=0^w.
 *  For j from 0 to l let RC[2^j-1]=rc(j+7ir).
 *  For all z such that 0<=z<w let A'[0,0,z]=A'[0,0,z]^RC[z]
 *
 *  rc(t) ->
 *  if t mod 255 == 0 return 1
 *  Let R= 10000000
 *  For i from 1 to t mod 255,
 *    a. R= 0 || R
 *    b. R[0]=R[0] ^ R[8]
 *    c. R[4]=R[4] ^ R[8]
 *    d. R[5]=R[5] ^ R[8]
 *    e. R[6]=R[6] ^ R[8]
 *    f. R=Trunc8[R]
 *  Return R[0]
 *
 */
PRUint64 RC[24] = {
    /* RC[ 0] */ 0x0000000000000001,
    /* RC[ 1] */ 0x0000000000008082,
    /* RC[ 2] */ 0x800000000000808A,
    /* RC[ 3] */ 0x8000000080008000,
    /* RC[ 4] */ 0x000000000000808B,
    /* RC[ 5] */ 0x0000000080000001,
    /* RC[ 6] */ 0x8000000080008081,
    /* RC[ 7] */ 0x8000000000008009,
    /* RC[ 8] */ 0x000000000000008A,
    /* RC[ 9] */ 0x0000000000000088,
    /* RC[10] */ 0x0000000080008009,
    /* RC[11] */ 0x000000008000000A,
    /* RC[12] */ 0x000000008000808B,
    /* RC[13] */ 0x800000000000008B,
    /* RC[14] */ 0x8000000000008089,
    /* RC[15] */ 0x8000000000008003,
    /* RC[16] */ 0x8000000000008002,
    /* RC[17] */ 0x8000000000000080,
    /* RC[18] */ 0x000000000000800A,
    /* RC[19] */ 0x800000008000000A,
    /* RC[20] */ 0x8000000080008081,
    /* RC[21] */ 0x8000000000008080,
    /* RC[22] */ 0x0000000080000001,
    /* RC[23] */ 0x8000000080008008
};

static inline void
sha3_iota(SHA3Context *ctx, int iR)
{
    PRUint64 *A = &ctx->A1[0];

    A[0] ^= RC[iR];
}

static inline void
sha3_Rnd(SHA3Context *ctx, int iR)
{
   sha3_theta(ctx);
   DUMP_BYTES("after Theta",ctx->A1);
   sha3_rho_pi(ctx);
   DUMP_BYTES("after Rho and Pi",ctx->A1);
   sha3_chi(ctx);
   DUMP_BYTES("after Chi",ctx->A1);
   sha3_iota(ctx, iR);
   DUMP_BYTES("after Iota",ctx->A1);
}

static inline void
Keccak_f(SHA3Context *ctx)
{
    int iR;
    for (iR=0; iR < 24; iR++) {
#ifdef TRACE
        printf("Round #%d\n",iR);
#endif
        sha3_Rnd(ctx,iR);
    }
}


static void
sha3_absorb(SHA3Context *ctx, const unsigned char *Nr, unsigned int r)
{
   /* convert to PRUint64's */
   unsigned int i;
   PRUint64 *A = &ctx->A1[0];
   PRUint64 *N = (PRUint64*)Nr;

   PORT_Assert((r & 0xf) == 0);
   DUMP_BUF("Data to be absorbed", Nr, r);

#ifdef PR_BIG_ENDIAN
#define INVERT_CTX(x) BYTESWAP8(A[x])
#else
#define INVERT_CTX(x)
#endif

   UNROLL25(INVERT_CTX);
   for (i = 0; i < r / sizeof(PRUint64); ++i) {
     A[i] ^= N[i];
   }
   UNROLL25(INVERT_CTX);

   DUMP_BYTES("Xor'd state(in bytes)",ctx->A1);
   DUMP_LANES("Xor'd state(as lanes)",ctx->A1);
   Keccak_f(ctx);
}

static inline void
sha3_update(SHA3Context *ctx, const unsigned char *N, unsigned int len,
                                                 unsigned int r)
{
    if (ctx->bufSize) {
        unsigned int fill = ctx->bufSize - r;
        if (fill < len) {
           PORT_Memcpy(&ctx->buf[ctx->bufSize], N, len);
           ctx->bufSize += len;
           return;
        }
        PORT_Memcpy(&ctx->buf[ctx->bufSize], N, fill);
        sha3_absorb(ctx, ctx->buf, r);
        ctx->bufSize= 0;
        N +=fill;
        len -= fill;
    }
    while (len >= r) {
        sha3_absorb(ctx, N, r);
        N += r;
        len -= r;
    }
    if (len) {
        PORT_Memcpy(ctx->buf, N, len);
        ctx->bufSize = len;
    }
}

/* domains include initial padding bit */
/* NOTE: domain values are bit strings of non-standard byte lengths. Since we
 * only support byte length hash bits, we know they always start on a byte
 * boundary. We also know that they will be followed up by the initial padding
 * bit. The final bit will be added as needed. Also know, bits go from right to
 * left (sigh) */
#define SHA3_DOMAIN      0x06
#define SHAKE_RAW_DOMAIN 0x07
#define SHAKE_DOMAIN     0x1f
#define SHA3_FINAL_PAD   0x80

static inline void
sha3_finalpad(SHA3Context *ctx, unsigned char domain, unsigned int r)
{
    ctx->buf[ctx->bufSize++] = domain;
    PORT_Memset(&ctx->buf[ctx->bufSize], 0, r-ctx->bufSize);
    ctx->buf[r-1] |= SHA3_FINAL_PAD;
    sha3_absorb(ctx, ctx->buf, r);
    ctx->bufSize = 0;
}

static inline void
sha3_unload_state(SHA3Context *ctx, unsigned char *Z, unsigned int d)
{
    /* now fill remainder of 'd' that is a multiple of 64 */
    PRUint64 *S = &ctx->A1[0];
    int i;
    while (d > sizeof(PRUint64)) {
        Z[0] =     *S     & 0xff;
        Z[1] = (*S >>  8) & 0xff;
        Z[2] = (*S >> 16) & 0xff;
        Z[3] = (*S >> 24) & 0xff;
        Z[4] = (*S >> 32) & 0xff;
        Z[5] = (*S >> 40) & 0xff;
        Z[6] = (*S >> 48) & 0xff;
        Z[7] = (*S >> 56) & 0xff;
        S++;
        Z += sizeof(PRUint64);
        d -= sizeof(PRUint64);
    }
    /* handle any remaining partials  (SHA224, for instance) */
    for (i=0; i < d; i++) {
        Z[i] = ((*S) >> (i*8)) &0xff;
    }
}

#ifdef SHAKE
/*
 * We currently don't have a need or use for SHAKE yet, but when we do,
 * this is what we need to implement it..
 */
static inline void
shake_squeeze(SHA3Context *ctx, unsigned int r, unsigned char *Z,
                                                unsigned int d)
{
    PORT_Assert((r & 0x7) == 0)

    /* first deal with any extra squeeses */
    while (d > r) {
        sha3_unload_state(ctx, Z, r);
        Z += r;
        d -= r;
        Keccak_f(ctx);
    }
    sha3_unload(ctx, Z, d);
}

static inline void
shake_final(SHA3Context *ctx, unsigned char domain, unsigned int r,
            unsigned char *Z, unsigned int d)
{
    sha3_finalpad(ctx, domain, r);
    shake_squeeze(ctx, r, Z, d);
}

static inline void
shake(unsigned char *message, unsigned int len, unsigned char *out,
                unsigned int outLen, unsigned char domain, unsigned int r)
{
    SHA3Context ctx;

    SHA3_Begin(&ctx);
    sha3_update(&ctx,message,len);
    sha3_finalpad(ctx, domain, r);
    shake_squeeze(ctx, r, out, outLen);
}


void
SHAKE128_Raw(unsigned char *message, unsigned int len,
             unsigned char *out, unsigned int outlen)
{
    shake(message, len, out, outLen, SHAKE_RAW_DOMAIN, SHAKE128_R);
}

void
SHAKE128(unsigned char *message, unsigned int len,
             unsigned char *out, unsigned int outlen)
{
    shake(message, len, out, outLen, SHAKE_DOMAIN, SHAKE128_R);
}

void
SHAKE256_Raw(unsigned char *message, unsigned int len,
             unsigned char *out, unsigned int outlen)
{
    shake(message, len, out, outLen, SHAKE_RAW_DOMAIN, SHAKE256_R);
}

void
SHAKE256(unsigned char *message, unsigned int len,
             unsigned char *out, unsigned int outlen)
{
    shake(message, len, out, outLen, SHAKE_DOMAIN, SHAKE256_R);
}

#endif


static inline void
sha3_final(SHA3Context *ctx, unsigned int r, unsigned char *Z, unsigned int d)
{
    sha3_finalpad(ctx, SHA3_DOMAIN, r);
    sha3_unload_state(ctx, Z, d);
}

/* constants in bytes, r = (b-c)/8 d = d/8 */
#define SHA3_224_R 144 /* (1600-448)/8 */
#define SHA3_224_D  28 /* (224)/8 */
#define SHA3_256_R 136 /* (1600-512)/8 */
#define SHA3_256_D  32 /* (256)/8 */
#define SHA3_384_R 104 /* (1600-768)/8 */
#define SHA3_384_D  48 /* (384)/8 */
#define SHA3_512_R  72 /* (1600-1024)/8 */
#define SHA3_512_D  64 /* (512)/8 */
#define SHAKE128_R 168 /* (1600-256)/8 */
#define SHAKE256_R 136 /* (1600-512)/8 */


SHA3Context *
SHA3_NewContext(void )
{
    SHA3Context *ctx = PORT_New(SHA3Context);
    return ctx;
}

void
SHA3_DestroyContext(SHA3Context *ctx, PRBool freeit)
{
    PORT_Memset(ctx, 0, sizeof (*ctx));
    if (freeit) {
        PORT_Free(ctx);
    }

}

void
SHA3_Begin(SHA3Context *ctx)
{
    PORT_Memset(ctx->A1, 0, sizeof(ctx->A1));
    PORT_Memset(ctx->A2, 0, sizeof(ctx->A1));
    PORT_Memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->bufSize = 0;
    DUMP_BYTES("State (in bytes)",ctx->A1);
}

unsigned int
SHA3_FlattenSize(SHA3Context *ctx)
{
    return sizeof *ctx;
}

SECStatus
SHA3_Flatten(SHA3Context *ctx,unsigned char *space)
{
    PORT_Memcpy(space, ctx, sizeof *ctx);
    return SECSuccess;
}

SHA3Context *
SHA3_Resurrect(unsigned char *space, void *arg)
{
    SHA3Context *ctx = SHA3_NewContext();
    if (ctx)
        PORT_Memcpy(ctx, space, sizeof *ctx);
    return ctx;
}

void
SHA3_224_Update(SHA3Context *ctx, const unsigned char *input,
                        unsigned int inputLength)
{
    sha3_update(ctx, input, inputLength, SHA3_224_R);
}

void
SHA3_224_End(SHA3Context *ctx, unsigned char *digest, unsigned int *digestLen,
                        unsigned int maxDigestLen)
{
    unsigned int maxLen = SHA_MIN(maxDigestLen, SHA3_224_D);
    sha3_final(ctx, SHA3_224_R, digest, maxDigestLen);
    *digestLen = maxLen;
}

SECStatus
SHA3_224_HashBuf(unsigned char *dest, const unsigned char *src,
               PRUint32 src_length)
{
    SHA3Context ctx;
    unsigned int outLen;

    SHA3_Begin(&ctx);
    sha3_update(&ctx, src, src_length, SHA3_224_R);
    sha3_final(&ctx, SHA3_224_R, dest, SHA3_224_D);
    memset(&ctx, 0, sizeof ctx);

    return SECSuccess;
}

SECStatus
SHA2_224_Hash(unsigned char *dest, const char *src)
{
    return SHA3_224_HashBuf(dest, (const unsigned char *)src, PORT_Strlen(src));
}


void
SHA3_256_Update(SHA3Context *ctx, const unsigned char *input,
                        unsigned int inputLength)
{
    sha3_update(ctx, input, inputLength, SHA3_256_R);
}

void
SHA3_256_End(SHA3Context *ctx, unsigned char *digest, unsigned int *digestLen,
                        unsigned int maxDigestLen)
{
    unsigned int maxLen = SHA_MIN(maxDigestLen, SHA3_256_D);
    sha3_final(ctx, SHA3_256_R, digest, maxDigestLen);
    *digestLen = maxLen;
}

SECStatus
SHA3_256_HashBuf(unsigned char *dest, const unsigned char *src,
               PRUint32 src_length)
{
    SHA3Context ctx;
    unsigned int outLen;

    SHA3_Begin(&ctx);
    sha3_update(&ctx, src, src_length, SHA3_256_R);
    sha3_final(&ctx, SHA3_256_R, dest, SHA3_256_D);
    memset(&ctx, 0, sizeof ctx);

    return SECSuccess;
}

SECStatus
SHA2_256_Hash(unsigned char *dest, const char *src)
{
    return SHA3_256_HashBuf(dest, (const unsigned char *)src, PORT_Strlen(src));
}

void
SHA3_384_Update(SHA3Context *ctx, const unsigned char *input,
                        unsigned int inputLength)
{
    sha3_update(ctx, input, inputLength, SHA3_384_R);
}

void
SHA3_384_End(SHA3Context *ctx, unsigned char *digest, unsigned int *digestLen,
                        unsigned int maxDigestLen)
{
    unsigned int maxLen = SHA_MIN(maxDigestLen, SHA3_384_D);
    sha3_final(ctx, SHA3_384_R, digest, maxDigestLen);
    *digestLen = maxLen;
}

SECStatus
SHA3_384_HashBuf(unsigned char *dest, const unsigned char *src,
               PRUint32 src_length)
{
    SHA3Context ctx;
    unsigned int outLen;

    SHA3_Begin(&ctx);
    sha3_update(&ctx, src, src_length, SHA3_384_R);
    sha3_final(&ctx, SHA3_384_R, dest, SHA3_384_D);
    memset(&ctx, 0, sizeof ctx);

    return SECSuccess;
}

SECStatus
SHA2_384_Hash(unsigned char *dest, const char *src)
{
    return SHA3_384_HashBuf(dest, (const unsigned char *)src, PORT_Strlen(src));
}

void
SHA3_512_Update(SHA3Context *ctx, const unsigned char *input,
                        unsigned int inputLength)
{
    sha3_update(ctx, input, inputLength, SHA3_512_R);
}

void
SHA3_512_End(SHA3Context *ctx, unsigned char *digest, unsigned int *digestLen,
                        unsigned int maxDigestLen)
{
    unsigned int maxLen = SHA_MIN(maxDigestLen, SHA3_512_D);
    sha3_final(ctx, SHA3_512_R, digest, maxDigestLen);
    *digestLen = maxLen;
}

SECStatus
SHA3_512_HashBuf(unsigned char *dest, const unsigned char *src,
               PRUint32 src_length)
{
    SHA3Context ctx;
    unsigned int outLen;

    SHA3_Begin(&ctx);
    sha3_update(&ctx, src, src_length, SHA3_512_R);
    sha3_final(&ctx, SHA3_512_R, dest, SHA3_512_D);
    memset(&ctx, 0, sizeof ctx);

    return SECSuccess;
}

SECStatus
SHA2_512_Hash(unsigned char *dest, const char *src)
{
    return SHA3_512_HashBuf(dest, (const unsigned char *)src, PORT_Strlen(src));
}


#ifdef TEST
main(int argc, char **argv)
{
 SHA3Context *ctx;
 unsigned char digest[SHA3_512_D];
 int len;

 unsigned char hash_input[] = {
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,
0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3,0xa3
};
 printf(" SHA3-224 0 bit message\n");
 ctx = SHA3_224_NewContext();
 SHA3_224_Begin(ctx);
 SHA3_224_End(ctx, digest, &len, sizeof(digest));
 dump_buf("Hash val is", digest, len);
 printf("\n");

 printf(" SHA3-256 0 bit message\n");
 ctx = SHA3_256_NewContext();
 SHA3_256_Begin(ctx);
 SHA3_256_End(ctx, digest, &len, sizeof(digest));
 dump_buf("Hash val is", digest, len);
 printf("\n");

 printf(" SHA3-384 0 bit message\n");
 ctx = SHA3_384_NewContext();
 SHA3_384_Begin(ctx);
 SHA3_384_End(ctx, digest, &len, sizeof(digest));
 dump_buf("Hash val is", digest, len);
 printf("\n");

 printf(" SHA3-512 0 bit message\n");
 ctx = SHA3_512_NewContext();
 SHA3_512_Begin(ctx);
 SHA3_512_End(ctx, digest, &len, sizeof(digest));
 dump_buf("Hash val is", digest, len);
 printf("\n");

 printf(" SHA3-224 1600 bit message\n");
 ctx = SHA3_224_NewContext();
 SHA3_224_Begin(ctx);
 SHA3_224_Update(ctx, hash_input, sizeof(hash_input));
 SHA3_224_End(ctx, digest, &len, sizeof(digest));
 dump_buf("Hash val is", digest, len);
 printf("\n");

 printf(" SHA3-256 1600 bit message\n");
 ctx = SHA3_256_NewContext();
 SHA3_256_Begin(ctx);
 SHA3_256_Update(ctx, hash_input, sizeof(hash_input));
 SHA3_256_End(ctx, digest, &len, sizeof(digest));
 dump_buf("Hash val is", digest, len);
 printf("\n");

 printf(" SHA3-384 1600 bit message\n");
 ctx = SHA3_384_NewContext();
 SHA3_384_Begin(ctx);
 SHA3_384_Update(ctx, hash_input, sizeof(hash_input));
 SHA3_384_End(ctx, digest, &len, sizeof(digest));
 dump_buf("Hash val is", digest, len);
 printf("\n");

 printf(" SHA3-512 1600 bit message\n");
 ctx = SHA3_512_NewContext();
 SHA3_512_Begin(ctx);
 SHA3_512_Update(ctx, hash_input, sizeof(hash_input));
 SHA3_512_End(ctx, digest, &len, sizeof(digest));
 dump_buf("Hash val is", digest, len);
 printf("\n");
}

#endif /* TEST */
