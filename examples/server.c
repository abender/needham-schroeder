#include "needham.h"
#include <string.h>

/* ---------------------------- Identity Storage --------------------------- */

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
    
  } else if(strcmp(identity_name, "smartobject-1") == 0) {
    char *daemon_key = "1111111111222222";
    memcpy(key, daemon_key, NS_RIN_KEY_LENGTH);
    return 0;
    
  } else if(strcmp(identity_name, "bender") == 0) {
    char *daemon_key = "1234567890123456";
    memcpy(key, daemon_key, NS_RIN_KEY_LENGTH);
    return 0;
    
  } else if(strcmp(identity_name, "rd_12345") == 0) {
    char *daemon_key = "1111111111222222";
    memcpy(key, daemon_key, NS_RIN_KEY_LENGTH);
    return 0;
    
  } else {
    return -1;
  }
}

/* ---------------------------- Network Handlers --------------------------- */

int send_to_peer(struct ns_context_t *context, ns_abstract_address_t *addr,
      uint8_t *data, size_t len) {
  
  return sendto( *((int*) context->app), data, len, MSG_DONTWAIT, &addr->addr.sa, addr->size);
}

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
  
  ns_context_t *context;
  char in_buffer[NS_SERVER_BUFFER_SIZE];
  int fd, read_bytes;
  int port = 50000;
  
  ns_abstract_address_t tmp_addr;
  memset(&tmp_addr, 0, sizeof(ns_abstract_address_t));
  tmp_addr.size = sizeof(tmp_addr.addr);
  
  ns_handler_t handler  = {
    .read = NULL,
    .write = send_to_peer,
    .store_key = NULL,
    .get_key = get_key,
    .event = NULL
  };
  
  fd = ns_bind_socket(port, AF_INET6);
  if(fd < 0)
    exit(-1);
  
  context = ns_initialize_context(&fd, &handler);
  if(!context) {
    ns_log_fatal("could not create context.");
    exit(-1);
  }

  ns_set_role(context, NS_ROLE_SERVER);
  
  ns_log_info("Server running (port: %d), waiting for key requests.", port);
  
  while(1) {
    read_bytes = recvfrom(fd, in_buffer, sizeof(in_buffer), 0, &tmp_addr.addr.sa, &tmp_addr.size);
    ns_handle_message(context, &tmp_addr, in_buffer, read_bytes);
  }
  
  ns_free_context(context);
  
  return 0;
}