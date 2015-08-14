/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _SHA_256_H_
#define _SHA_256_H_

struct SHA256ContextStr {
    union {
	uint32_t w[64];	    /* message schedule, input buffer, plus 48 words */
	uint8_t  b[256];
    } u;
    uint32_t h[8];		/* 8 state variables */
    uint32_t sizeHi,sizeLo;	/* 64-bit count of hashed bytes. */
};

#endif /* _SHA_256_H_ */
