# sha3

HARD HAT AREA

This repo is just my working notes on trying to implement SHA-3.  Ultimately, I
would like to come up with something that can get contributed to NSS.

The first iteration was to see how well I could do just from the spec, with just
the optimizations that occurred naturally to me.  That appears to have gotten
performance to about 10x the NSS SHA-2 implementation (in terms of cycles/byte).

The next step is probably to try to improve performance.  That will probably
involve looking at the optimizations applied by the Keccak authors in their
optimized implementation, and perhaps taking some techniques from the NSS SHA-2
implementation.

## Quickstart

```
gcc sha3.c correctness_test.c && ./a.out
gcc sha3.c sha512.o speed_test.c && ./a.out
```

## Credits

The measurement bits in `speed_test.c` are taken from the measurement code
included with the [C implementation](http://keccak.noekeon.org/KeccakReferenceAndOptimized-3.2.zip) distributed by the Keccak authors.
