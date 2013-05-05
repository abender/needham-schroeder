#include "needham.h"
#include "uthash.h"

typedef struct {
  UT_hash_handle hh;
  char name[NS_IDENTITY_LENGTH];
  char key[NS_KEY_LENGTH];
} identity_t;

identity_t *identities = NULL;

int store_key(char *identity_name, char *key) {
  
  identity_t *id;
  id = malloc(sizeof(identity_t));
  
  memcpy(id->name, identity_name, NS_IDENTITY_LENGTH);
  memcpy(id->key, key, NS_KEY_LENGTH);
  
  HASH_ADD_STR(identities, name, id);
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

int main(int argc, char **argv) {
  
  int port = 50002;
  char *key = "1111111111222222";
  ns_daemon_handler_t handler  = {
    .store_key = store_key,
    .get_key = get_key
  };
  
  ns_daemon(&handler, port, key);
  
  return 0;
}