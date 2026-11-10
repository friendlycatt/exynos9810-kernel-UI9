/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compatibility shim for the SHA-1 primitives.
 *
 * This tree still provides the legacy SHA-1 helpers in <linux/cryptohash.h>
 * (sha_init()/sha_transform() with SHA_DIGEST_WORDS/SHA_WORKSPACE_WORDS).
 * Newer kernel code (the backported BPF core in particular) uses the
 * sha1_* naming and constants from <crypto/sha1.h>; map them onto the
 * legacy API so both spellings keep working.
 */

#ifndef _CRYPTO_SHA1_H
#define _CRYPTO_SHA1_H

#include <crypto/sha.h>
#include <linux/cryptohash.h>

#define SHA1_DIGEST_WORDS	SHA_DIGEST_WORDS
#define SHA1_WORKSPACE_WORDS	SHA_WORKSPACE_WORDS

#define sha1_init		sha_init
#define sha1_transform		sha_transform

#endif /* _CRYPTO_SHA1_H */
