#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "test_vectors_0.h"

typedef struct ContextStr {
  // Sponge state
  uint64_t A[5][5];

  // Temporary storage for in-place [chi]
  uint64_t B[5];

  // Temporary column sums [theta]
  uint64_t C[5];

  // Temporary per-column addends [theta]
  uint64_t D[5];
} Context;

uint64_t swap_endian(uint64_t x) {
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
      printf("%016llx ", (swap)? swap_endian(S[y][x]) : S[y][x]);
    }
    printf("\n");
  }
  printf("\n");
}

void dump_tv_diff(uint64_t a[5][5], uint64_t tv[5][5]) {
  int x,y;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      printf("%016llx ", swap_endian(a[y][x]) ^ tv[y][x]);
    }
    printf("\n");
  }
  printf("\n");
}

int statecmp(uint64_t a[5][5], uint64_t tv[5][5], int round, int step) {
  int x,y;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      if (swap_endian(a[y][x]) != tv[y][x]) {
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

uint64_t mod5(x) {
  return (x >= 0)? (x%5) : 5 - (-1*x % 5);
}

uint64_t rotl(uint64_t x, int n) {
  return (x << n) | (x >> (64 - n));
}

void theta(Context* ctx) {
  int x,y;
  uint64_t C[5];
  for (x = 0; x < 5; ++x) {
    C[x] = ctx->A[0][x] ^ ctx->A[1][x] ^ ctx->A[2][x] ^ ctx->A[3][x] ^ ctx->A[4][x];
  }

  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      ctx->A[y][x] ^= C[mod5(x-1)] ^ rotl(C[mod5(x+1)], 1);
    }
  }
}


static const size_t rho_offsets[5][5] = {
  { 0,  1, 62, 28, 27},
  {36, 44,  6, 55, 20},
  { 3, 10, 43, 25, 39},
  {41, 45, 15, 21,  8},
  {18,  2, 61, 56, 14}
};

void rho(Context* ctx) {
  int x,y;
  for (x = 0; x < 5; ++x) {
    for (y = 0; y < 5; ++y) {
      ctx->A[y][x] = rotl(ctx->A[y][x], rho_offsets[y][x]);
    }
  }
}

// Pre-computed coordinate transformations
static const int N[4][5][5] = {
};


static const int pi_x[5][5] = {
  {0, 3, 1, 4, 2},
  {1, 4, 2, 0, 3},
  {2, 0, 3, 1, 4},
  {3, 1, 4, 2, 0},
  {4, 2, 0, 3, 1}
};

void pi(Context* ctx) {
  int x,y;
  Context tmp;
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
}

#define ONE 0xFFFFFFFFFFFFFFFF

void chi(Context* ctx) {
  int x,y;
  Context tmp;
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
}

/*
uint64_t rc(int t) {
  uint16_t R = 1;
  for (int i=0; i < t % 255; ++i) {
    R <<= 1;
    R ^= (R >> 8)? 0x71 : 0x00;
    R &= 0xFF;
  }
  return (R%2)? ONE : 0;
}

uint64_t RC(int ir) {
  uint64_t RC = 0;
  uint64_t one = 1;
  for (int j = 0;  j<=6; ++j) {
    RC |= (one << ((1<<j)-1)) & rc(j + 7*ir);
  }
  return RC;
}
*/

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

void iota(Context* ctx, int ir) {
  ctx->A[0][0] ^= RC[ir];
}


int rnd(Context* ctx, int ir) {
  printf("=== Round %d ===\n\n", ir);

  theta(ctx);
  if (!statecmp(ctx->A, test_vectors_0[ir][0], ir, 0)) return 0;

  rho(ctx);
  if (!statecmp(ctx->A, test_vectors_0[ir][1], ir, 1)) return 0;

  pi(ctx);
  if (!statecmp(ctx->A, test_vectors_0[ir][2], ir, 2)) return 0;

  chi(ctx);
  if (!statecmp(ctx->A, test_vectors_0[ir][3], ir, 3)) return 0;

  iota(ctx, ir);
  if (!statecmp(ctx->A, test_vectors_0[ir][4], ir, 4)) return 0;

  return 1;
}


int main() {
  Context ctx;
  memset(ctx.A, 0, sizeof(ctx.A));

  ctx.A[0][0] = 0x0000000000000006;
  ctx.A[3][1] = 0x8000000000000000;

  for (int ir=0; ir<24; ++ir) {
    if (!rnd(&ctx, ir)) return 0;
  }

  return 1;
}
