#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "test_vectors_1600.h"

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

void dump_input(const uint8_t *input, const size_t len) {
  for (int i=0; i<len; ++i) {
    printf("%02X", input[i]);
  }
  printf("\n");
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

  // rho
  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      ctx->A[y][x] = rotl(ctx->A[y][x], rho_offsets[y][x]);
    }
  }

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

  // iota
  ctx->A[0][0] ^= RC[ir];

  return 1;
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

int BLOCK = 0;

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
    ctx->todoLength += inputLen;
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
  ctx->todoLength = inputLen - used;
  memset(ctx->todo, 0, MAX_TODO);
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
  SHA3_AddBlock(ctx, ctx->todo);

  // Return Trunc_d(Z), in the proper byte order
  // TODO support further squeezing for SHAKE
  copy_from_sponge(digest, ctx, ctx->d);
  *digestLen = ctx->d;
}

#define MESSAGE_LEN_SHORT_SHORT 1
const uint8_t message_short_short[MESSAGE_LEN_SHORT_SHORT] = { 0xCC };

#define MESSAGE_LEN_SHORT 200
const uint8_t message_short[MESSAGE_LEN_SHORT] = {
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3, 0xA3,
};


#define MESSAGE_LEN_LONG 382
const uint8_t message_long[MESSAGE_LEN_LONG] = {
  0x02, 0x3D, 0x91, 0xAC, 0x53, 0x26, 0x01, 0xC7, 0xCA, 0x39,
  0x42, 0xD6, 0x28, 0x27, 0x56, 0x6D, 0x92, 0x68, 0xBB, 0x42,
  0x76, 0xFC, 0xAA, 0x1A, 0xE9, 0x27, 0x69, 0x3A, 0x69, 0x61,
  0x65, 0x26, 0x76, 0xDB, 0xA0, 0x92, 0x19, 0xA0, 0x1B, 0x3D,
  0x5A, 0xDF, 0xA1, 0x25, 0x47, 0xA9, 0x46, 0xE7, 0x8F, 0x3C,
  0x5C, 0x62, 0xDD, 0x88, 0x0B, 0x02, 0xD2, 0xEE, 0xEB, 0x4B,
  0x96, 0x63, 0x65, 0x29, 0xC6, 0xB0, 0x11, 0x20, 0xB2, 0x3E,
  0xFC, 0x49, 0xCC, 0xFB, 0x36, 0xB8, 0x49, 0x7C, 0xD1, 0x97,
  0x67, 0xB5, 0x37, 0x10, 0xA6, 0x36, 0x68, 0x3B, 0xC5, 0xE0,
  0xE5, 0xC9, 0x53, 0x4C, 0xFC, 0x00, 0x46, 0x91, 0xE8, 0x7D,
  0x1B, 0xEE, 0x39, 0xB8, 0x6B, 0x95, 0x35, 0x72, 0x92, 0x7B,
  0xD6, 0x68, 0x62, 0x0E, 0xAB, 0x87, 0x83, 0x6D, 0x9F, 0x3F,
  0x8F, 0x28, 0xAC, 0xE4, 0x11, 0x50, 0x77, 0x6C, 0x0B, 0xC6,
  0x65, 0x71, 0x78, 0xEB, 0xF2, 0x97, 0xFE, 0x1F, 0x72, 0x14,
  0xED, 0xD9, 0xF2, 0x15, 0xFF, 0xB4, 0x91, 0xB6, 0x81, 0xB0,
  0x6A, 0xC2, 0x03, 0x2D, 0x35, 0xE6, 0xFD, 0xF8, 0x32, 0xA8,
  0xB0, 0x60, 0x56, 0xDA, 0x70, 0xD7, 0x7F, 0x1E, 0x9B, 0x4D,
  0x26, 0xAE, 0x71, 0x2D, 0x85, 0x23, 0xC8, 0x6F, 0x79, 0x25,
  0x07, 0x18, 0x40, 0x5F, 0x91, 0xB0, 0xA8, 0x7C, 0x72, 0x5F,
  0x2D, 0x3F, 0x52, 0x08, 0x89, 0x65, 0xF8, 0x87, 0xD8, 0xCF,
  0x87, 0x20, 0x6D, 0xFD, 0xE4, 0x22, 0x38, 0x6E, 0x58, 0xED,
  0xDA, 0x34, 0xDD, 0xE2, 0x78, 0x3B, 0x30, 0x49, 0xB8, 0x69,
  0x17, 0xB4, 0x62, 0x80, 0x27, 0xA0, 0x5D, 0x4D, 0x1F, 0x42,
  0x9D, 0x2B, 0x49, 0xC4, 0xB1, 0xC8, 0x98, 0xDD, 0xDC, 0xB8,
  0x2F, 0x34, 0x3E, 0x14, 0x55, 0x96, 0xDE, 0x11, 0xA5, 0x41,
  0x82, 0xF3, 0x9F, 0x47, 0x18, 0xEC, 0xAE, 0x8F, 0x50, 0x6B,
  0xD9, 0x73, 0x9F, 0x5C, 0xD5, 0xD5, 0x68, 0x6D, 0x7F, 0xEF,
  0xC8, 0x34, 0x51, 0x4C, 0xD1, 0xB2, 0xC9, 0x1C, 0x33, 0xB3,
  0x81, 0xB4, 0x5E, 0x2E, 0x53, 0x35, 0xD7, 0xA8, 0x72, 0x0A,
  0x8F, 0x17, 0xAF, 0xC8, 0xC2, 0xCB, 0x2B, 0xD8, 0x8B, 0x14,
  0xAA, 0x2D, 0xCA, 0x09, 0x9B, 0x00, 0xAA, 0x57, 0x5D, 0x0A,
  0x0C, 0xCF, 0x09, 0x9C, 0xDE, 0xC4, 0x87, 0x0F, 0xB7, 0x10,
  0xD2, 0x68, 0x0E, 0x60, 0xC4, 0x8B, 0xFC, 0x29, 0x1F, 0xF0,
  0xCE, 0xF2, 0xEE, 0xBF, 0x9B, 0x36, 0x90, 0x2E, 0x9F, 0xBA,
  0x8C, 0x88, 0x9B, 0xF6, 0xB4, 0xB9, 0xF5, 0xCE, 0x53, 0xA1,
  0x9B, 0x0D, 0x93, 0x99, 0xCD, 0x19, 0xD6, 0x1B, 0xD0, 0x8C,
  0x0C, 0x2E, 0xC2, 0x5E, 0x09, 0x99, 0x59, 0x84, 0x8E, 0x6A,
  0x55, 0x0C, 0xA7, 0x13, 0x7B, 0x63, 0xF4, 0x31, 0x38, 0xD7,
  0xB6, 0x51
};

// Extremely long test from KeccakKAT
// text = abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno
#define REPEAT 16777216
#define MESSAGE_LEN_EXT_LONG 64
const uint8_t message_ext_long[MESSAGE_LEN_EXT_LONG] = {
  0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x62, 0x63,
  0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x63, 0x64, 0x65, 0x66,
  0x67, 0x68, 0x69, 0x6a, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
  0x6a, 0x6b, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
  0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x67, 0x68,
  0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x68, 0x69, 0x6a, 0x6b,
  0x6c, 0x6d, 0x6e, 0x6f
};

// Vary this to choose among the SHA3-* variants
#define DIGEST_LEN 224 / 8

int main() {
  unsigned int digestLen;
  uint8_t *digest = malloc(DIGEST_LEN);

  SHA3Context *ctx = SHA3_NewContext();
  SHA3_Begin(ctx, DIGEST_LEN, 0, 0); // domain=0/0 for raw Keccak
  // Single-shot test
  // SHA3_Update(ctx, message_long, MESSAGE_LEN_LONG);
  // Repeated test
  for (int i=0; i<REPEAT; ++i) {
    printf("%9d\r", i);
    SHA3_Update(ctx, message_ext_long, MESSAGE_LEN_EXT_LONG);
  }
  printf("\n");

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

// Test vectors for 8-bit KeccakKAT input (using domain=0/0, for raw Keccak)
//
// SHA3-224   tv    A9CAB59EB40A10B246290F2D6086E32E3689FAF1D26B470C899F2802
//            me    A9CAB59EB40A10B246290F2D6086E32E3689FAF1D26B470C899F2802
// SHA3-256   tv    EEAD6DBFC7340A56CAEDC044696A168870549A6A7F6F56961E84A54BD9970B8A
//            me    EEAD6DBFC7340A56CAEDC044696A168870549A6A7F6F56961E84A54BD9970B8A
// SHA3-384   tv    1B84E62A46E5A201861754AF5DC95C4A1A69CAF4A796AE405680161E29572641F5FA1E8641D7958336EE7B11C58F73E9
//            me    1B84E62A46E5A201861754AF5DC95C4A1A69CAF4A796AE405680161E29572641F5FA1E8641D7958336EE7B11C58F73E9
// SHA3-512   tv    8630C13CBD066EA74BBE7FE468FEC1DEE10EDC1254FB4C1B7C5FD69B646E44160B8CE01D05A0908CA790DFB080F4B513BC3B6225ECE7A810371441A5AC666EB9
//            me    8630C13CBD066EA74BBE7FE468FEC1DEE10EDC1254FB4C1B7C5FD69B646E44160B8CE01D05A0908CA790DFB080F4B513BC3B6225ECE7A810371441A5AC666EB9

// Test vectors for 200*0xA3 input
// SHA3-224   tv    9376816ABA503F72F96CE7EB65AC095DEEE3BE4BF9BBC2A1CB7E11E0
//            me    9376816ABA503F72F96CE7EB65AC095DEEE3BE4BF9BBC2A1CB7E11E0
// SHA3-256   tv    79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787
//            me    79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787
// SHA3-384   tv    1881DE2CA7E41EF95DC4732B8F5F002B189CC1E42B74168ED1732649CE1DBCDD76197A31FD55EE989F2D7050DD473E8F
//            me    1881DE2CA7E41EF95DC4732B8F5F002B189CC1E42B74168ED1732649CE1DBCDD76197A31FD55EE989F2D7050DD473E8F
// SHA3-512   tv    E76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA81B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00
//            me    E76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA81B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00

// Test vectors for 3056-bit input from KeccakKAT (using domain=0/0, for raw Keccak)
// SHA3-224   tv    230620D710CF3AB835059E1AA170735DB17CAE74B345765FF02E8D89
//            me    230620D710CF3AB835059E1AA170735DB17CAE74B345765FF02E8D89
// SHA3-256   tv    6C2A841318066B90A9604D0C8ECCB2986B84A0C8675CD243E96957D26E9C1CFD
//            me    6C2A841318066B90A9604D0C8ECCB2986B84A0C8675CD243E96957D26E9C1CFD
// SHA3-384   tv    AE559C732E55C521B7731E9C8065931B93AB5EF16728E3F3C738E7D507B18489388CC3CA7BA01AF672C22CB767C295D2
//            me    AE559C732E55C521B7731E9C8065931B93AB5EF16728E3F3C738E7D507B18489388CC3CA7BA01AF672C22CB767C295D2
// SHA3-512   tv    218A55796529149F29CC4A19C80E05C26F048ABC9894AD79F11BAC7C28DE53BDC9BDB8BE4984F924640867FCFCE42310ADFA949E2B2568FFA0795FBB3203DE65
//            me    218A55796529149F29CC4A19C80E05C26F048ABC9894AD79F11BAC7C28DE53BDC9BDB8BE4984F924640867FCFCE42310ADFA949E2B2568FFA0795FBB3203DE65

// Test vectors for the extremely long (1GB) input from KeccakKAT (using domain=0/0, for raw Keccak)
// SHA3-224   tv    C42E4AEE858E1A8AD2976896B9D23DD187F64436EE15969AFDBC68C5
//            me    C42E4AEE858E1A8AD2976896B9D23DD187F64436EE15969AFDBC68C5
// SHA3-256   tv    5F313C39963DCF792B5470D4ADE9F3A356A3E4021748690A958372E2B06F82A4
//            me    5F313C39963DCF792B5470D4ADE9F3A356A3E4021748690A958372E2B06F82A4
// SHA3-384   tv    9B7168B4494A80A86408E6B9DC4E5A1837C85DD8FF452ED410F2832959C08C8C0D040A892EB9A755776372D4A8732315
//            me    9B7168B4494A80A86408E6B9DC4E5A1837C85DD8FF452ED410F2832959C08C8C0D040A892EB9A755776372D4A8732315
// SHA3-512   tv    3E122EDAF37398231CFACA4C7C216C9D66D5B899EC1D7AC617C40C7261906A45FC01617A021E5DA3BD8D4182695B5CB785A28237CBB167590E34718E56D8AAB8
//            me    3E122EDAF37398231CFACA4C7C216C9D66D5B899EC1D7AC617C40C7261906A45FC01617A021E5DA3BD8D4182695B5CB785A28237CBB167590E34718E56D8AAB8
