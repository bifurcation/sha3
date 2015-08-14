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

uint64_t swap_endian_lane(uint64_t x) {
  int i;
  uint64_t y = 0;
  for (i = 0; i < 8; ++i) {
    y <<= 8;
    y |= (x%0x100);
    x >>= 8;
  }
  return y;
}

// This lets us just memcpy / xor to byte arrays
void
swap_endian(SHA3Context *ctx) {
  for (int x=0; x<5; ++x) {
    for (int y=0; y<5; ++y) {
      // TODO Just do this in-place?
      ctx->A[y][x] = swap_endian_lane(ctx->A[y][x]);
    }
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

// Parentheses are abundant here, but necessary in order to get
// the expected operator precedence while saving the function
// call overhead
#define rotl(x, n)  (((x) << n) | ((x) >> (64 - n)))

static const size_t rho_offsets[5][5] = {
  { 0,  1, 62, 28, 27},
  {36, 44,  6, 55, 20},
  { 3, 10, 43, 25, 39},
  {41, 45, 15, 21,  8},
  {18,  2, 61, 56, 14}
};

static const int pi_inv[5][5] = {
  {0, 2, 4, 1, 3},
  {3, 0, 2, 4, 1},
  {1, 3, 0, 2, 4},
  {4, 1, 3, 0, 2},
  {2, 4, 1, 3, 0}
};

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

const int mod5m1[5] = {4, 0, 1, 2, 3}; // (x-1) mod 5
const int mod5p1[5] = {1, 2, 3, 4, 0}; // (x+1) mod 5
const int mod5p2[5] = {2, 3, 4, 0, 1}; // (x+2) mod 5

int rnd(SHA3Context* ctx, int ir) {
  int x,y;

  // theta/2
  for (x = 0; x < 5; ++x) {
    ctx->C[x] = ctx->A[0][x] ^ ctx->A[1][x] ^ ctx->A[2][x] ^ ctx->A[3][x] ^ ctx->A[4][x];
  }

  // theta/2 + rho
  for (x = 0; x < 5; ++x) {
    ctx->D[x] = ctx->C[mod5m1[x]] ^ rotl(ctx->C[mod5p1[x]], 1);

    for (y = 0; y < 5; ++y) {
      ctx->B[pi_inv[y][x]][y] = rotl(ctx->A[y][x] ^ ctx->D[x], rho_offsets[y][x]);
    }
  }

  // chi
  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      ctx->A[y][x] = ctx->B[y][x] ^
                     (ctx->B[y][mod5p1[x]] ^ ONE) &
                     ctx->B[y][mod5p2[x]];
    }
  }

  // iota
  ctx->A[0][0] ^= RC[ir];

  return 1;
}

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
  for (int ir=0; ir<24; ++ir) {
    rnd(ctx, ir);
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

/*
#include <stdio.h>

int main() {
  int inv_x[5][5];
  int inv_y[5][5];

  for (int y=0; y<5; ++y) {
    for (int x=0; x<5; ++x) {
      inv_x[y][pi_x[x][y]] = x;
      inv_y[y][pi_x[x][y]] = y;
    }
  }

  for (int y=0; y<5; ++y) {
    for (int x=0; x<5; ++x) {
      int x1 = y;
      int y1 = pi_x[y][x];
      int x2 = inv_x[x1][y1];
      int y2 = x1;
      printf("(%d, %d) -> (%d, %d) -> (%d, %d) \n", x, y, x1, y1, x2, y2);
    }
    printf("\n");
  }

  printf("inv_x = {\n");
  for (int y=0; y<5; ++y) {
    printf("  {%d, %d, %d, %d, %d},\n", inv_x[y][0], inv_x[y][1], inv_x[y][2], inv_x[y][3], inv_x[y][4]);
  }
  printf("}\n");

  printf("inv_y = {\n");
  for (int y=0; y<5; ++y) {
    printf("  {%d, %d, %d, %d, %d},\n", inv_y[y][0], inv_y[y][1], inv_y[y][2], inv_y[y][3], inv_y[y][4]);
  }
  printf("}\n");

  return 0;
}
*/
