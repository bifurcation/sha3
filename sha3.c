#include <stdlib.h>
#include <string.h>
#include "sha3.h"

#define SHA3_HASH_DOMAIN      0x02
#define SHA3_HASH_DOMAIN_LEN  2
#define SHA3_XOF_DOMAIN       0xFF
#define SHA3_XOF_DOMAIN_LEN   4

SHA3Context *
SHA3_NewContext(void)
{
  SHA3Context *ctx = PORT_New(SHA3Context);
  return ctx;
}

void
SHA3_DestroyContext(SHA3Context *ctx, PRBool freeit)
{
  memset(ctx, 0, sizeof *ctx);
  if (freeit) {
    PORT_Free(ctx);
  }
}

/* This is where the context gets specialized to a  specific SHA3 function. */
void
sha3_begin(SHA3Context *ctx, size_t d, uint8_t domain, uint8_t domainLength)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->d = d;
  ctx->r = 200 - 2*d; /* TODO XOF */
  ctx->domain = domain;
  ctx->domainLength = domainLength;
}

/* For computing raw Keccak, without the domain separator */
void
SHA3_Raw_Begin(SHA3Context *ctx, size_t d)
{
  sha3_begin(ctx, d, 0, 0);
}

void
SHA3_224_Begin(SHA3Context *ctx)
{
  sha3_begin(ctx, 28, SHA3_HASH_DOMAIN, SHA3_HASH_DOMAIN_LEN);
}

void
SHA3_256_Begin(SHA3Context *ctx)
{
  sha3_begin(ctx, 32, SHA3_HASH_DOMAIN, SHA3_HASH_DOMAIN_LEN);
}

void
SHA3_384_Begin(SHA3Context *ctx)
{
  sha3_begin(ctx, 48, SHA3_HASH_DOMAIN, SHA3_HASH_DOMAIN_LEN);
}

void
SHA3_512_Begin(SHA3Context *ctx)
{
  sha3_begin(ctx, 64, SHA3_HASH_DOMAIN, SHA3_HASH_DOMAIN_LEN);
}

/****************************************************************/

#if defined(_MSC_VER)
#pragma intrinsic(_rotr64,_rotl64)
#define ROTR64(x,n) _rotr64(x,n)
#define ROTL64(x,n) _rotl64(x,n)
#else
#define ROTR64(x,n) ((x >> n) | (x << (64 - n)))
#define ROTL64(x,n) ((x << n) | (x >> (64 - n)))
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
#define SHA_HTONLL(x) (t1 = x, \
  t1 = ((t1 & SHA_MASK8 ) <<  8) | ((t1 >>  8) & SHA_MASK8 ), \
  t1 = ((t1 & SHA_MASK16) << 16) | ((t1 >> 16) & SHA_MASK16), \
  (t1 >> 32) | (t1 << 32))
#endif
#define BYTESWAP8(x) x = SHA_HTONLL(x)

#define CTX_A(x, y) ctx->A[y * 5 + x]
#define CTX_B(x, y) ctx->B[y * 5 + x]
#define CTX_C(x) ctx->C[x]
#define CTX_D(x) ctx->D[x]

// This lets us just memcpy / xor to byte arrays
void
swap_endian(SHA3Context *ctx) {
  for (int i=0; i<25; ++i) {
    BYTESWAP8(ctx->A[i]);
  }
}

// With these #defines, we only incur endiannes-swapping cost
// on big-endian platforms
#ifdef PR_BIG_ENDIAN
#define TO_LITTLE_ENDIAN(ctx) swap_endian(ctx)
#define FROM_LITTLE_ENDIAN(ctx) swap_endian(ctx)
#else
#define TO_LITTLE_ENDIAN(ctx)
#define FROM_LITTLE_ENDIAN(ctx)
#endif

#define rho_offsets(y,x) rho_offsets_ ## y ## _ ## x
#define rho_offsets_0_0 0
#define rho_offsets_0_1 1
#define rho_offsets_0_2 62
#define rho_offsets_0_3 28
#define rho_offsets_0_4 27
#define rho_offsets_1_0 36
#define rho_offsets_1_1 44
#define rho_offsets_1_2 6
#define rho_offsets_1_3 55
#define rho_offsets_1_4 20
#define rho_offsets_2_0 3
#define rho_offsets_2_1 10
#define rho_offsets_2_2 43
#define rho_offsets_2_3 25
#define rho_offsets_2_4 39
#define rho_offsets_3_0 41
#define rho_offsets_3_1 45
#define rho_offsets_3_2 15
#define rho_offsets_3_3 21
#define rho_offsets_3_4 8
#define rho_offsets_4_0 18
#define rho_offsets_4_1 2
#define rho_offsets_4_2 61
#define rho_offsets_4_3 56
#define rho_offsets_4_4 14

#define pi_inv(y,x) pi_inv_ ## y ## _ ## x
#define pi_inv_0_0 0
#define pi_inv_0_1 2
#define pi_inv_0_2 4
#define pi_inv_0_3 1
#define pi_inv_0_4 3
#define pi_inv_1_0 3
#define pi_inv_1_1 0
#define pi_inv_1_2 2
#define pi_inv_1_3 4
#define pi_inv_1_4 1
#define pi_inv_2_0 1
#define pi_inv_2_1 3
#define pi_inv_2_2 0
#define pi_inv_2_3 2
#define pi_inv_2_4 4
#define pi_inv_3_0 4
#define pi_inv_3_1 1
#define pi_inv_3_2 3
#define pi_inv_3_3 0
#define pi_inv_3_4 2
#define pi_inv_4_0 2
#define pi_inv_4_1 4
#define pi_inv_4_2 1
#define pi_inv_4_3 3
#define pi_inv_4_4 0


#define ONE 0xFFFFFFFFFFFFFFFF

// Pre-computed round constants
uint64_t RC[24] = {
  0x0000000000000001,
  0x0000000000008082,
  0x800000000000808a,
  0x8000000080008000,
  0x000000000000808b,
  0x0000000080000001,
  0x8000000080008081,
  0x8000000000008009,
  0x000000000000008a,
  0x0000000000000088,
  0x0000000080008009,
  0x000000008000000a,
  0x000000008000808b,
  0x800000000000008b,
  0x8000000000008089,
  0x8000000000008003,
  0x8000000000008002,
  0x8000000000000080,
  0x000000000000800a,
  0x800000008000000a,
  0x8000000080008081,
  0x8000000000008080,
  0x0000000080000001,
  0x8000000080008008
};

// Do the mod operations in the preprocessor
#define mod5m1(x) mod5m1_ ## x
#define mod5m1_0 4
#define mod5m1_1 0
#define mod5m1_2 1
#define mod5m1_3 2
#define mod5m1_4 3
#define mod5p1(x) mod5p1_ ## x
#define mod5p1_0 1
#define mod5p1_1 2
#define mod5p1_2 3
#define mod5p1_3 4
#define mod5p1_4 0
#define mod5p2(x) mod5p2_ ## x
#define mod5p2_0 2
#define mod5p2_1 3
#define mod5p2_2 4
#define mod5p2_3 0
#define mod5p2_4 1

// Macros to make loop unrolling prettier
#define COL_SUM(x) \
  CTX_C(x) = CTX_A(x, 0) ^ CTX_A(x, 1) ^ CTX_A(x, 2) ^ CTX_A(x, 3) ^ CTX_A(x, 4);
#define TRP_COL(x) \
  CTX_D(x) = CTX_C(mod5m1(x)) ^ ROTL64(CTX_C(mod5p1(x)), 1);    \
  TRP_ROW(0, x) \
  TRP_ROW(1, x) \
  TRP_ROW(2, x) \
  TRP_ROW(3, x) \
  TRP_ROW(4, x)
#define TRP_ROW(y, x) \
  CTX_B(y, pi_inv(y,x)) = ROTL64(CTX_A(x, y) ^ CTX_D(x), rho_offsets(y, x));
#define CHI_ROW(y) \
  CHI_COL(y, 0) \
  CHI_COL(y, 1) \
  CHI_COL(y, 2) \
  CHI_COL(y, 3) \
  CHI_COL(y, 4)
#define CHI_COL(y, x) \
  CTX_A(x, y) = CTX_B(x, y) ^ (CTX_B(mod5p1(x), y) ^ ONE) & CTX_B(mod5p2(x), y);
#define ROUND(ctx, ir) \
  /* theta/2 */ \
  COL_SUM(0); \
  COL_SUM(1); \
  COL_SUM(2); \
  COL_SUM(3); \
  COL_SUM(4); \
  /* theta/2 + rho + pi */ \
  TRP_COL(0); \
  TRP_COL(1); \
  TRP_COL(2); \
  TRP_COL(3); \
  TRP_COL(4); \
  /* chi */ \
  CHI_ROW(0); \
  CHI_ROW(1); \
  CHI_ROW(2); \
  CHI_ROW(3); \
  CHI_ROW(4); \
  /* iota */ \
  CTX_A(0, 0) ^= RC[ir];

// The input buffer is expected to have at least ctx->r bytes.
void
add_block(SHA3Context *ctx, const unsigned char *input)
{
  // XOR and apply permutation
  TO_LITTLE_ENDIAN(ctx);
  uint8_t *state = (uint8_t*) ctx->A;
  for (int i=0; i<ctx->r; ++i) {
    state[i] ^= input[i];
  }
  FROM_LITTLE_ENDIAN(ctx);

  // Emprically, unrolling this loop doesn't help
  for (int ir=0; ir<24; ++ir) {
    ROUND(ctx, ir);
  }
}

void
SHA3_Update(SHA3Context *ctx, const unsigned char *input,
                        unsigned int inputLen)
{
  // If we still haven't made a full block, just buffer
  if (ctx->todoLength + inputLen < ctx->r) {
    memcpy(ctx->todo + ctx->todoLength, input, inputLen);
    ctx->todoLength += inputLen;
    return;
  }

  // First block: ctx->todo + remainder of block from input
  unsigned int used = ctx->r - ctx->todoLength;
  memcpy(ctx->todo + ctx->todoLength, input, used);
  add_block(ctx, ctx->todo);
  memset(ctx->todo, 0, sizeof(ctx->todo));

  // Remaining blocks read from input while remaining length > ctx->r
  while (inputLen - used > ctx->r) {
    add_block(ctx, input + used);
    used += ctx->r;
  }

  // Finally, copy trailing input to ctx->todo
  ctx->todoLength = inputLen - used;
  memset(ctx->todo, 0, sizeof(ctx->todo));
  memcpy(ctx->todo, input + used, ctx->todoLength);
}

void
SHA3_End(SHA3Context *ctx, unsigned char *digest,
         unsigned int *digestLen, unsigned int maxDigestLen)
{
  if (maxDigestLen < ctx->d) {
    // TODO how to fail more gracefully?  PORT_SetError?
    return;
  }

  // Write domain tag to ctx->todo buffer
  // This is safe because ctx->todoLen is always less than ctx->r.
  // Otherwise, we would have processed the block in SHA3_Update.
  ctx->todo[ctx->todoLength] = ctx->domain;

  // pad10*1 => Write a 1 after the domain, and at the end
  ctx->todo[ctx->todoLength] |= (1 << ctx->domainLength);
  ctx->todo[ctx->r - 1] |= 0x80;

  // Apply permutation
  add_block(ctx, ctx->todo);

  // Return Trunc_d(Z), in the proper byte order
  // TODO support further squeezing for SHAKE
  TO_LITTLE_ENDIAN(ctx);
  memcpy(digest, (uint8_t*) ctx->A, ctx->d);
  FROM_LITTLE_ENDIAN(ctx);
  *digestLen = ctx->d;
}
