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

#include "ns_util.h"

#ifdef CONTIKI
#include "lib/random.h"
#endif /* CONTIKI */


/* ---------------------------- Random Stuff ------------------------------- */

#ifndef CONTIKI
static void ns_random(char *dst, size_t length, const char *chars, size_t chars_len) {

  FILE *file;
  char line[length];
  memset(line, 0, sizeof(char) * sizeof(line));
  
  file = fopen(NS_RANDOM_PATH, "r");
  if(file == NULL) {
    ns_log_fatal("Unable to open \"%s\" which is needed to generate "
        "randoms.", NS_RANDOM_PATH);
    exit(-1); /* FIXME: proper handling */
  }
  
  if(fgets(line, length+1, file) == NULL) {
    ns_log_fatal("Couldn't get enough characters from \"%s\" to "
      "create the random key.", NS_RANDOM_PATH);
    exit(-1);  /* FIXME: proper handling */
  }
  
  int i;
  for(i = 0; i < length; i++) {
    dst[i] = chars[line[i] % chars_len];
  }
  fclose(file);
}
#else /* CONTIKI */
static void ns_random(char *dst, size_t length, const char *chars, size_t chars_len) {
  
  unsigned short ran;
  char *p = dst;
  while(p - dst < length) {
    ran = random_rand();
    memcpy(p, &chars[(ran % chars_len)], 1);
    p++;
  }
}
#endif /* CONTIKI */

void ns_random_identity(char *dst, size_t length) {
  
  const char ns_identity_characters[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '@' };
  
  ns_random(dst, length, ns_identity_characters, sizeof(ns_identity_characters));
  
}

void ns_random_key(char *dst, size_t length) {

/* FIXME these are only 84 possibilities for each key charakter, so with a
   total of 16 Bytes Key-length, the actual possibilites are
   84^16 =~ 6 * 10^30 instead of 256^16 =~ 3 * 10^38.
   
   This is done for testing purposes and easy human readable keys and needs
   to be changed for productive environments! */

  const char ns_key_characters[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '@', '<', '>', '(', ')', '{', '}', '/', '!', '?', '$', '%', '&', '#', '*',
    '-', '+', '.', ',', ';', ':', '_' };

  ns_random(dst, length, ns_key_characters, sizeof(ns_key_characters));

}

/* ------------------------------- Logging --------------------------------- */

void ns_simple_log(int level, int app_level, char *msg, ...) {

#ifndef CONTIKI
  if(app_level <= level) {
    
    char *levels[] = { "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };
    
    printf("%s: ", levels[level]);
    va_list ap;
    va_start(ap, msg);
    vprintf(msg, ap);
    va_end(ap);
    printf("\n");
  
    fflush(stdout);
  }
#else /* CONTIKI */

#define LOG_BUFLEN 150
  if(app_level <= level) {
    va_list args;
    int bytes_written = 0;
    char log_buf[LOG_BUFLEN];

    memset(log_buf, 0, LOG_BUFLEN);
  
    va_start(args, msg);
    bytes_written = vsnprintf(log_buf, LOG_BUFLEN, msg, args);
  
    /* indicate if log was truncated due to a small log buffer */
    if(bytes_written > LOG_BUFLEN)
      memcpy(log_buf + LOG_BUFLEN - 14, " (truncated)\n", 13);
    
    va_end(args);
#undef LOG_BUFLEN
    printf("%s\n", log_buf);
  }

#endif /* CONTIKI */
}

void ns_dump_bytes_to_hex(unsigned char *bytes, size_t length) {
  int i;
  for(i = 0; i < length; i++) {
    printf("%02x ", bytes[i]);
  }
  printf("\n");
}

void ns_dump_bytes_to_bin(unsigned char *bytes, size_t length) {
  int i;
  for(i = 0; i < length; i++) {
    ns_dump_byte_to_bin(&bytes[i]);
    printf(" ");
    if((i != 0) && ((i+1) % 4) == 0) {
      printf("\n");
    }
  }
  printf("\n");
}

void ns_dump_byte_to_hex(unsigned char *b) {
  printf("%02x\n", *b);
}

void ns_dump_byte_to_bin(unsigned char *b) {
  int i;
  for(i = 7; i >= 0; i--) {
    printf("%d", ((*b & (1 << i)) != 0));
  }
}
