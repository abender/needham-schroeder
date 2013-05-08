#include "needham.h"
#include "uthash.h"

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

int main(int argc, char **argv) {
  
  int port = 50002;
  char *key = "1111111111222222";
  char *identity = "example_daemon";
  ns_daemon_handler_t handler  = {
    .store_key = store_key,
    .get_key = get_key
  };
  
  ns_daemon(&handler, port, identity, key);
  
  return 0;
}