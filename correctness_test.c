#include <stdio.h>
#include <string.h>
#include "sha3.h"
#include "test_vectors.h"

// These are the test vectors we will use to check correctess
// as we edit things
// From the 1600-bit SHA3 test
const char *d224 = "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0";
const char *d256 = "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787";
const char *d384 = "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd"
                   "76197a31fd55ee989f2d7050dd473e8f";
const char *d512 = "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8"
                   "1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00";

void hexcmp(const char* tv, uint8_t *digest, size_t digestLen) {
  size_t hexlen = 2*digestLen;
  char *hex = (char*) malloc(hexlen+1);
  memset(hex, 0, hexlen+1);
  for (int i=0; i<digestLen; ++i) {
    sprintf(hex + 2*i, "%02x", digest[i]);
  }

  if (strncmp(tv, hex, hexlen) != 0) {
    printf("[%lu] FAIL\n%s\n%s\n", digestLen * 8, tv, hex);
  } else {
    printf("[%lu] OK\n", digestLen * 8);
  }
}

#define MAX_DIGEST_SIZE 64

int main() {
  unsigned int digestLen;
  uint8_t digest[MAX_DIGEST_SIZE];
  SHA3Context *ctx = SHA3_NewContext();

  SHA3_224_Begin(ctx);
  SHA3_Update(ctx, message_short, MESSAGE_LEN_SHORT);
  SHA3_End(ctx, digest, &digestLen, MAX_DIGEST_SIZE);
  hexcmp(d224, digest, digestLen);

  SHA3_256_Begin(ctx);
  SHA3_Update(ctx, message_short, MESSAGE_LEN_SHORT);
  SHA3_End(ctx, digest, &digestLen, MAX_DIGEST_SIZE);
  hexcmp(d256, digest, digestLen);

  SHA3_384_Begin(ctx);
  SHA3_Update(ctx, message_short, MESSAGE_LEN_SHORT);
  SHA3_End(ctx, digest, &digestLen, MAX_DIGEST_SIZE);
  hexcmp(d384, digest, digestLen);

  SHA3_256_Begin(ctx);
  SHA3_Update(ctx, message_short, MESSAGE_LEN_SHORT);
  SHA3_End(ctx, digest, &digestLen, MAX_DIGEST_SIZE);
  hexcmp(d256, digest, digestLen);

  SHA3_DestroyContext(ctx, PR_TRUE);
  return 0;
}
