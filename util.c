/**
 * simple Needham-Schroeder implementation
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

#include "util.h"

/* ---------------------------- Random Stuff ------------------------------- */

void ns_random_key(char *dst, size_t length) {
  
  const char key_characters[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '@', '<', '>', '(', ')', '{', '}', '/', '!', '?', '$', '%', '&', '#', '*',
    '-', '+', '.', ',', ';', ':', '_' };
  
  FILE *file;
  char line[length];
  
  file = fopen(NS_RANDOM_PATH, "r");
  if(file == NULL) {
    ns_log_fatal("Unable to open \"%s\" which is needed to generate "
        "random keys.", NS_RANDOM_PATH);
    exit(EXIT_FAILURE);
  }
  
  if(fgets(line, length+1, file) == NULL) {
    ns_log_fatal("Couldn't get enough characters from \"%s\" to "
      "create the random key.", NS_RANDOM_PATH);
    exit(EXIT_FAILURE);
  }
  
  int i;
  for(i = 0; i < length; i++) {
    dst[i] = key_characters[line[i] % sizeof(key_characters)];
  }
  fclose(file);
}

/* ------------------------------- Logging --------------------------------- */

void ns_simple_log(int level, int app_level, char *msg, ...) {
  
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
}

void ns_dump_bytes_to_hex(char *bytes, size_t length) {
  int i;
  for(i = 0; i < length; i++) {
    printf("%02x ", (u_char) bytes[i]);
  }
  printf("\n");
}

void ns_dump_bytes_to_bin(char *bytes, size_t length) {
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

void ns_dump_byte_to_hex(char *b) {
  printf("%02x\n", *b);
}

void ns_dump_byte_to_bin(char *b) {
  int i;
  for(i = 7; i >= 0; i--) {
    printf("%d", ((*b & (1 << i)) != 0));
  }
  fflush(stdout);
}