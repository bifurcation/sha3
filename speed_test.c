#include <stdlib.h>
#include <stdio.h>
#include "sha3.h"
#include "sha2.h"

/*

This test attempts to measure the speed of the SHA-3 implementations
by having them hash a large buffer.  The buffer is processed in a
single call to SHA3_Update, in order to avoid counting overhead from
that function.

*/

/*
 * Timing functions borrowed from the Keccak reference implementation,
 * simplified by assuming GCC on my laptop.
 */
uint32_t
HiResTime(void)
{
  uint32_t x[2];
  asm volatile("rdtsc" : "=a"(x[0]), "=d"(x[1]));
  return x[0];
}

#define TIMER_SAMPLE_CNT (100)

uint32_t calibrate()
{
    uint32_t dtMin = 0xFFFFFFFF;        /* big number to start */
    uint32_t t0,t1,i;

    for (i=0;i < TIMER_SAMPLE_CNT;i++)  /* calibrate the overhead for measuring time */
        {
        t0 = HiResTime();
        t1 = HiResTime();
        if (dtMin > t1-t0)              /* keep only the minimum time */
            dtMin = t1-t0;
        }
    return dtMin;
}

uint8_t*
randomBuffer(size_t size)
{
  uint8_t *r = (uint8_t*) malloc(size);
  for (int i=0; i<size; ++i) {
    r[i] = random() & 0xFF;
  }
  return r;
}

uint32_t measureRandomBuffer_224(uint32_t dtMin, size_t size)
{
    uint32_t tMin = 0xFFFFFFFF;
    uint32_t t0,t1,i;
    unsigned char *input = randomBuffer(size);
    SHA3Context *ctx = SHA3_NewContext();
    unsigned char digest[64];
    unsigned int digestLen;

    for (i=0;i < TIMER_SAMPLE_CNT;i++) {
        t0 = HiResTime();

        SHA3_224_Begin(ctx);
        SHA3_Update(ctx, input, size);
        SHA3_End(ctx, digest, &digestLen, 64);

        t1 = HiResTime();
        if (tMin > t1-t0 - dtMin) {
            tMin = t1-t0 - dtMin;
        }
    }

    /* now tMin = # clocks required for running RoutineToBeTimed() */
    SHA3_DestroyContext(ctx, 1);
    free(input);
    return tMin;
}

uint32_t measureRandomBuffer_256(uint32_t dtMin, size_t size)
{
    uint32_t tMin = 0xFFFFFFFF;
    uint32_t t0,t1,i;
    unsigned char *input = randomBuffer(size);
    SHA3Context *ctx = SHA3_NewContext();
    unsigned char digest[64];
    unsigned int digestLen;

    for (i=0;i < TIMER_SAMPLE_CNT;i++) {
        t0 = HiResTime();

        SHA3_256_Begin(ctx);
        SHA3_Update(ctx, input, size);
        SHA3_End(ctx, digest, &digestLen, 64);

        t1 = HiResTime();
        if (tMin > t1-t0 - dtMin) {
            tMin = t1-t0 - dtMin;
        }
    }

    /* now tMin = # clocks required for running RoutineToBeTimed() */
    SHA3_DestroyContext(ctx, 1);
    free(input);
    return tMin;
}

uint32_t measureRandomBuffer_384(uint32_t dtMin, size_t size)
{
    uint32_t tMin = 0xFFFFFFFF;
    uint32_t t0,t1,i;
    unsigned char *input = randomBuffer(size);
    SHA3Context *ctx = SHA3_NewContext();
    unsigned char digest[64];
    unsigned int digestLen;

    for (i=0;i < TIMER_SAMPLE_CNT;i++) {
        t0 = HiResTime();

        SHA3_384_Begin(ctx);
        SHA3_Update(ctx, input, size);
        SHA3_End(ctx, digest, &digestLen, 64);

        t1 = HiResTime();
        if (tMin > t1-t0 - dtMin) {
            tMin = t1-t0 - dtMin;
        }
    }

    /* now tMin = # clocks required for running RoutineToBeTimed() */
    SHA3_DestroyContext(ctx, 1);
    free(input);
    return tMin;
}

uint32_t measureRandomBuffer_512(uint32_t dtMin, size_t size)
{
    uint32_t tMin = 0xFFFFFFFF;
    uint32_t t0,t1,i;
    unsigned char *input = randomBuffer(size);
    SHA3Context *ctx = SHA3_NewContext();
    unsigned char digest[64];
    unsigned int digestLen;

    for (i=0;i < TIMER_SAMPLE_CNT;i++) {
        t0 = HiResTime();

        SHA3_512_Begin(ctx);
        SHA3_Update(ctx, input, size);
        SHA3_End(ctx, digest, &digestLen, 64);

        t1 = HiResTime();
        if (tMin > t1-t0 - dtMin) {
            tMin = t1-t0 - dtMin;
        }
    }

    /* now tMin = # clocks required for running RoutineToBeTimed() */
    SHA3_DestroyContext(ctx, 1);
    free(input);
    return tMin;
}

uint32_t measureRandomBuffer_SHA256(uint32_t dtMin, size_t size)
{
    uint32_t tMin = 0xFFFFFFFF;
    uint32_t t0,t1,i;
    unsigned char *input = randomBuffer(size);
    SHA256Context *ctx = SHA256_NewContext();
    unsigned char digest[64];
    unsigned int digestLen;

    for (i=0;i < TIMER_SAMPLE_CNT;i++) {
        t0 = HiResTime();

        SHA256_Begin(ctx);
        SHA256_Update(ctx, input, size);
        SHA256_End(ctx, digest, &digestLen, 64);

        t1 = HiResTime();
        if (tMin > t1-t0 - dtMin) {
            tMin = t1-t0 - dtMin;
        }
    }

    /* now tMin = # clocks required for running RoutineToBeTimed() */
    free(input);
    return tMin;
}

uint32_t measureRandomBuffer_SHA512(uint32_t dtMin, size_t size)
{
    uint32_t tMin = 0xFFFFFFFF;
    uint32_t t0,t1,i;
    unsigned char *input = randomBuffer(size);
    SHA512Context *ctx = SHA512_NewContext();
    unsigned char digest[64];
    unsigned int digestLen;

    for (i=0;i < TIMER_SAMPLE_CNT;i++) {
        t0 = HiResTime();

        SHA512_Begin(ctx);
        SHA512_Update(ctx, input, size);
        SHA512_End(ctx, digest, &digestLen, 64);

        t1 = HiResTime();
        if (tMin > t1-t0 - dtMin) {
            tMin = t1-t0 - dtMin;
        }
    }

    /* now tMin = # clocks required for running RoutineToBeTimed() */
    free(input);
    return tMin;
}


int main()
{
  srandom(HiResTime());

  uint32_t calibration = calibrate();
  printf("Calibration: %d\n\n", calibration);

  int i;
  uint32_t measurement;
  const char *format = "%10d => %10.2f\n";
  const int testSizes[4] = {1, 100, 10000, 1000000};

  printf("=== SHA-256 ===\n");
  for (i=0; i<4; ++i) {
    measurement = measureRandomBuffer_SHA256(calibration, testSizes[i]);
    printf(format, testSizes[i], measurement * 1.0 / testSizes[i]);
  }
  printf("\n");

  printf("=== SHA-512 ===\n");
  for (i=0; i<4; ++i) {
    measurement = measureRandomBuffer_SHA512(calibration, testSizes[i]);
    printf(format, testSizes[i], measurement * 1.0 / testSizes[i]);
  }
  printf("\n");

  printf("=== SHA3-224 ===\n");
  for (i=0; i<4; ++i) {
    measurement = measureRandomBuffer_224(calibration, testSizes[i]);
    printf(format, testSizes[i], measurement * 1.0 / testSizes[i]);
  }
  printf("\n");

  printf("=== SHA3-256 ===\n");
  for (i=0; i<4; ++i) {
    measurement = measureRandomBuffer_224(calibration, testSizes[i]);
    printf(format, testSizes[i], measurement * 1.0 / testSizes[i]);
  }
  printf("\n");

  printf("=== SHA3-384 ===\n");
  for (i=0; i<4; ++i) {
    measurement = measureRandomBuffer_224(calibration, testSizes[i]);
    printf(format, testSizes[i], measurement * 1.0 / testSizes[i]);
  }
  printf("\n");

  printf("=== SHA3-512 ===\n");
  for (i=0; i<4; ++i) {
    measurement = measureRandomBuffer_224(calibration, testSizes[i]);
    printf(format, testSizes[i], measurement * 1.0 / testSizes[i]);
  }
  printf("\n");
}
