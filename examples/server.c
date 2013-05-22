#include "needham.h"
#include <string.h>

/**
 * Callback function to get a key for \p identity_name. This function could
 * get identity-key-pairs from a database for example. Keys must have the length
 * of NS_RIN_KEY_LENGTH bytes.
 *
 * In this example the server knows the identities "example_client" and
 * "example_daemon" and their corresponding keys. A return value of -1 indicates
 * an unknown \p identity_name.
 */
int get_key(char *identity_name, char *key) {
  
  if(strcmp(identity_name, "example_client") == 0) {
    char *client_key = "0123456789012345";
    memcpy(key, client_key, NS_RIN_KEY_LENGTH);
    return 0;
    
  } else if(strcmp(identity_name, "example_daemon") == 0) {
    char *daemon_key = "1111111111222222";
    memcpy(key, daemon_key, NS_RIN_KEY_LENGTH);
    return 0;
    
  } else {
    return -1;
  }
}

int main(int argc, char **argv) {
  
  int port = 50000;
  ns_server_handler_t handler = {
    .get_key = get_key
  };
  
  ns_server(&handler, port);
  
  return 0;
}