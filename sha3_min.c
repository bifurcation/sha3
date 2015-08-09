#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "test_vectors_0.h"

// Bogus stuff NSPR
typedef int PRBool; // totes bogus
#define PORT_New(x) malloc(sizeof(x))
#define PORT_Free(x) free(x)
#define PR_FALSE 0
#define PR_TRUE 1

#define DEBUG 0
#define MAX_TODO 144

// All of the SHA3 functions use a common context struct
typedef struct SHA3ContextStr {
  // Length of the expected output, in bytes
  // SHA3-224 => 1152 bits = 144
  // SHA3-256 => 1088 bits = 136
  // SHA3-384 =>  832 bits = 104
  // SHA3-512 =>  576 bits =  72
  // SHAKE128 => as specified
  // SHAKE256 => as specified
  size_t d;

  // Width of the sponge input function, in bytes
  // SHA3-d   => 1600 - 2*d bits = 200 - 2*d bytes
  // SHAKE128 => 1600 - 256
  // SHAKE256 => 1600 - 512
  size_t r;

  // Context for usage
  // Hash = 01
  // XOF  = 1111
  uint8_t domain;
  uint8_t domainLength;

  // A buffer to hold pending input
  uint8_t todo[MAX_TODO];
  uint8_t todoLength;

  // Sponge state
  uint64_t A[5][5];

  // Temporary storage for in-place [chi]
  uint64_t B[5];

  // Temporary column sums [theta]
  uint64_t C[5];

  // Temporary per-column addends [theta]
  uint64_t D[5];
} SHA3Context;

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

// This is where the context gets specialized to a
// specific SHA3 function.
void
SHA3_Begin(SHA3Context *ctx, size_t d, uint8_t domain, uint8_t domainLength)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->d = d;
  ctx->r = 200 - 2*d; // TODO Support XOF variants.
  ctx->domain = domain;
  ctx->domainLength = domainLength;
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

void dump(uint64_t S[5][5], int swap) {
  int x,y;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      printf("%016llx ", (swap)? swap_endian_lane(S[y][x]) : S[y][x]);
    }
    printf("\n");
  }
  printf("\n");
}

void dump_tv_diff(uint64_t a[5][5], uint64_t tv[5][5]) {
  int x,y;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      printf("%016llx ", swap_endian_lane(a[y][x]) ^ tv[y][x]);
    }
    printf("\n");
  }
  printf("\n");
}

int statecmp(uint64_t a[5][5], uint64_t tv[5][5], int round, int step) {
  if (!DEBUG) {
    return 1;
  }

  int x,y;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      if (swap_endian_lane(a[y][x]) != tv[y][x]) {
        printf("[%02d] [%02d] FAIL\n", round, step);
        dump(a, 1);
        dump(tv, 0);
        dump_tv_diff(a, tv);

        return 0;
      }
    }
  }
  printf("[%02d] [%02d] OK\n", round, step);
  return 1;
}

/****************************************************************/

uint64_t mod5(x) {
  return (x >= 0)? (x%5) : 5 - (-1*x % 5);
}

uint64_t rotl(uint64_t x, int n) {
  return (x << n) | (x >> (64 - n));
}

static const size_t rho_offsets[5][5] = {
  { 0,  1, 62, 28, 27},
  {36, 44,  6, 55, 20},
  { 3, 10, 43, 25, 39},
  {41, 45, 15, 21,  8},
  {18,  2, 61, 56, 14}
};

static const int pi_x[5][5] = {
  {0, 3, 1, 4, 2},
  {1, 4, 2, 0, 3},
  {2, 0, 3, 1, 4},
  {3, 1, 4, 2, 0},
  {4, 2, 0, 3, 1}
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

int rnd(SHA3Context* ctx, int ir) {
  int x,y;
  SHA3Context tmp;
  printf("=== Round %d ===\n\n", ir);

  // theta
  uint64_t C[5];
  for (x = 0; x < 5; ++x) {
    C[x] = ctx->A[0][x] ^ ctx->A[1][x] ^ ctx->A[2][x] ^ ctx->A[3][x] ^ ctx->A[4][x];
  }

  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      ctx->A[y][x] ^= C[mod5(x-1)] ^ rotl(C[mod5(x+1)], 1);
    }
  }
  if (!statecmp(ctx->A, test_vectors_0[ir][0], ir, 0)) return 0;

  // rho
  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      ctx->A[y][x] = rotl(ctx->A[y][x], rho_offsets[y][x]);
    }
  }
  if (!statecmp(ctx->A, test_vectors_0[ir][1], ir, 1)) return 0;

  // pi
  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      tmp.A[y][x] = ctx->A[x][pi_x[x][y]];
    }
  }
  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      ctx->A[y][x] = tmp.A[y][x];
    }
  }
  if (!statecmp(ctx->A, test_vectors_0[ir][2], ir, 2)) return 0;

  // chi
  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      tmp.A[y][x] = (ctx->A[y][mod5(x+1)] ^ ONE) & ctx->A[y][mod5(x+2)];
    }
  }

  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      ctx->A[y][x] ^= tmp.A[y][x];
    }
  }
  if (!statecmp(ctx->A, test_vectors_0[ir][3], ir, 3)) return 0;

  // iota
  ctx->A[0][0] ^= RC[ir];
  if (!statecmp(ctx->A, test_vectors_0[ir][4], ir, 4)) return 0;

  return 1;
}

// This lets us just memcpy / xor to byte arrays
void
swap_endian(SHA3Context *ctx) {
  printf("~~~ BEFORE ENDIAN SWAP ~~~\n");
  dump(ctx->A, 1);

  for (int x=0; x<5; ++x) {
    for (int y=0; y<5; ++y) {
      // TODO Just do this in-place?
      ctx->A[y][x] = swap_endian_lane(ctx->A[y][x]);
    }
  }

  printf("~~~ AFTER ENDIAN SWAP ~~~\n");
  dump(ctx->A, 1);
}

// These can be changed to noops with an #ifdef
#ifdef PR_BIG_ENDIAN
#define TO_LITTLE_ENDIAN(ctx) swap_endian(ctx)
#define FROM_LITTLE_ENDIAN(ctx) swap_endian(ctx)
#else
#define TO_LITTLE_ENDIAN(ctx)
#define FROM_LITTLE_ENDIAN(ctx)
#endif

void
add_to_sponge(SHA3Context *ctx, const unsigned char *input)
{
  TO_LITTLE_ENDIAN(ctx);
  uint8_t *state = (uint8_t*) ctx->A;
  for (int i=0; i<ctx->r; ++i) {
    state[i] ^= input[i];
  }
  FROM_LITTLE_ENDIAN(ctx);
}

// In the notation of the spec:
//   A[x,y,z] = S[w(5y+x) + z]
void
copy_from_sponge(uint8_t *dst, SHA3Context *ctx, size_t length)
{
  TO_LITTLE_ENDIAN(ctx);
  memcpy(dst, (uint8_t*) ctx->A, length);
  FROM_LITTLE_ENDIAN(ctx);
}

// The input buffer is expected to have at least ctx->r bytes.
void
SHA3_AddBlock(SHA3Context *ctx, const unsigned char *input)
{
  // XOR and apply permutation
  add_to_sponge(ctx, input);
  for (int ir=0; ir<24; ++ir) {
    rnd(ctx, ir);
  }
}

void
SHA3_Update(SHA3Context *ctx, const unsigned char *input,
		        unsigned int inputLen)
{
  // If we still haven't made a full block, just add to TODO
  if (ctx->todoLength + inputLen < ctx->r) {
    memcpy(ctx->todo + ctx->todoLength, input, inputLen);
    return;
  }

  // First block: ctx->todo + remainder of block from input
  unsigned int used = ctx->r - ctx->todoLength;
  memcpy(ctx->todo + ctx->todoLength, input, used);
  SHA3_AddBlock(ctx, ctx->todo);
  memset(ctx->todo, 0, MAX_TODO);

  // Remaining blocks read from input while remaining length > ctx->r
  while (inputLen - used > ctx->r) {
    SHA3_AddBlock(ctx, input + used);
    used += ctx->r;
  }

  // Finally, copy trailing input to ctx->todo
  memcpy(ctx->todo, input + used, inputLen - used);
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
  SHA3_AddBlock(ctx, ctx->todo);

  // Return Trunc_d(Z), in the proper byte order
  // TODO support further squeezing for SHAKE
  copy_from_sponge(digest, ctx, ctx->d);
  *digestLen = ctx->d;
}

// Vary this to choose among the SHA3-* variants
#define DIGEST_LEN 256 / 8

int main() {
  unsigned int digestLen;
  uint8_t *digest = malloc(DIGEST_LEN);

  SHA3Context *ctx = SHA3_NewContext();
  SHA3_Begin(ctx, DIGEST_LEN, 2, 2);
  SHA3_End(ctx, digest, &digestLen, DIGEST_LEN);

  printf("digest len = %d\n", digestLen);
  printf("digest     = ");
  for (int i=0; i<digestLen; ++i) {
    printf("%02X", digest[i]);
  }
  printf("\n");

  SHA3_DestroyContext(ctx, PR_TRUE);

  return 0;
}

// Test vectors for null input
//
// SHA3-224   tv    6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7
//            me    6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7
// SHA3-256   tv    A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A
//            me    A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A
// SHA3-384   tv    0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004
//            me    0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004
// SHA3-512   tv    A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26
//            me    A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26


