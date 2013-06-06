#include "needham.h"

/* ---------------------------- Identity Storage --------------------------- */

typedef struct {
  UT_hash_handle hh;
  char name[NS_IDENTITY_LENGTH];
  char key[NS_KEY_LENGTH];
} identity_t;

identity_t *identities = NULL;

/**
 * store_key may be called more than once, this callback should update the
 * existing identity if it is already present in the data storage.
 */
int store_key(char *identity_name, char *key) {
  
  identity_t *id;
  HASH_FIND_STR(identities, identity_name, id);
  
  /* identity not found, insert a new one */
  if(id == NULL) {
    id = malloc(sizeof(identity_t));
    memcpy(id->name, identity_name, NS_IDENTITY_LENGTH);
    memcpy(id->key, key, NS_KEY_LENGTH);
    HASH_ADD_STR(identities, name, id);
    
  /* identity was already present, update the key */
  } else {
    memcpy(id->key, key, NS_KEY_LENGTH);    
  }
  return 0;
}

int get_key(char *identity_name, char *key) {
  
  identity_t *id = NULL;
  HASH_FIND_STR(identities, identity_name, id);

  if(id) {
    memcpy(key, id->key, NS_KEY_LENGTH);
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
  char in_buffer[NS_DAEMON_BUFFER_SIZE];
  int fd, read_bytes;
  
  ns_abstract_address_t tmp_addr;
  memset(&tmp_addr, 0, sizeof(ns_abstract_address_t));
  tmp_addr.size = sizeof(tmp_addr.addr);
  
  int port = 50010;
  char *key = "1111111111222222";
  char *identity = "example_daemon";

  ns_handler_t handler  = {
    .read = NULL,
    .write = send_to_peer,
    .store_key = store_key,
    .get_key = get_key,
    .event = NULL
  };
  
  fd = ns_bind_socket(port, AF_INET6);
  
  context = ns_initialize_context(&fd, &handler);
  if(!context) {
    ns_log_fatal("could not create context.");
    exit(-1);
  }
  
  ns_set_credentials(context, identity, key);
  
  ns_set_role(context, NS_ROLE_DAEMON);
  
  ns_log_info("listening on port %d", port);
  
  while(1) {
    read_bytes = recvfrom(fd, in_buffer, sizeof(in_buffer), 0, &tmp_addr.addr.sa, &tmp_addr.size);
    ns_handle_message(context, &tmp_addr, in_buffer, read_bytes);
  }
  
  ns_free_context(context);
  
  return 0;
}