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

#ifndef _NS_UTILITIES_
#define _NS_UTILITIES_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>

/* ---------------------------- Random Stuff ------------------------------- */

#define NS_RANDOM_PATH "/dev/random"

/*
 * Creates a random key of \p length Bytes and stores it in \p dst .
 */
void ns_random_key(char *dst, size_t length);

/*
 * Creates a random identity of \p length Bytes and stores it in \p dst .
 * Uses a different set of characters to create identities.
 */
void ns_random_identity(char *dst, size_t length);

/* ------------------------------- Logging --------------------------------- */

#define NS_LOG_LEVEL 0

/*
 * Prints \p msg to stdout if \p level is >= "app_level"
 */
void ns_simple_log(int level, int app_level, char *msg, ...);

#define ns_log_debug(...) ns_simple_log(0, NS_LOG_LEVEL, __VA_ARGS__)
#define ns_log_info(...) ns_simple_log(1, NS_LOG_LEVEL, __VA_ARGS__)
#define ns_log_warning(...) ns_simple_log(2, NS_LOG_LEVEL, __VA_ARGS__)
#define ns_log_error(...) ns_simple_log(3, NS_LOG_LEVEL, __VA_ARGS__)
#define ns_log_fatal(...) ns_simple_log(4, NS_LOG_LEVEL, __VA_ARGS__)

void ns_dump_bytes_to_hex(unsigned char *bytes, size_t length);

void ns_dump_bytes_to_bin(unsigned char *bytes, size_t length);

void ns_dump_byte_to_hex(unsigned char *b);

void ns_dump_byte_to_bin(unsigned char *b);

#endif // _NS_UTILITIES_