/**
 * simple extended Needham-Schroeder implementation
 *
 * Copyright (c) 2013 Andreas Bender <bender@tzi.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _RIN_WRAPPER_H_
#define _RIN_WRAPPER_H_

#include "rijndael/rijndael.h"

#include <stdlib.h>

#define NS_BLOCK_SIZE 16

void ns_dump(unsigned char *buf, size_t len);

/*
 * Like "encrypt" but adds PKCS7 padding ( http://tools.ietf.org/html/rfc5652#section-6.3 )
 * if needed. Therefore \p dst must be a multiple of BLOCK_SIZE and big enough to hold
 * \p src .
 */
int ns_encrypt_pkcs7(u_char *key, u_char *src, u_char *dst, size_t length, size_t key_length);

/**
 * Encrypts \p src with \p key. \p dst must have at least the size of \p src.
 *
 * \param key        The Key used by encryption
 * \param src        The cleartext
 * \param dst        Pointer to a buffer where the ciphertext will be stored.
 *                     Must be at least of the size of \p src.
 * \param length     Length of the cleartext
 * \param key_length Key length in Bytes.(128 Key = 16 Bytes.)
 * \return Zero on success.
 */
int ns_encrypt(u_char *key, u_char *src, u_char *dst, size_t length, size_t key_length);

/*
 * Like encrypt, but \p src is a ciphertext which will be decrypted and stored
 * in \p dst.
 */
int ns_decrypt(u_char *key, u_char *src, u_char *dst, size_t length, size_t key_length);

/*
 * Just for debugging purposes.
 */
int ns_test_encryption();

#endif /* _RIN_WRAPPER_H_ */