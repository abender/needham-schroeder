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

int result(int code) {
  printf("needham-schroeder finished its negotiation with exit code %d.\n", code);
  return 0;
}

void print_identities() {
  identity_t *id = NULL;
  int i = 0;
  if(identities) {
    for(id = identities; id != NULL; id = id->hh.next) {
      printf("%d - name : %s, key : %s\n", i, id->name, id->key);
    }
  } else {
    printf("- no identities stored -\n");
  }
}

int main(int argc, char **argv) {
  
  char *server_address = "127.0.0.1";
  char *partner_address = "127.0.0.1";
  
  int server_port = 50000;
  int partner_port = 50002;
  int client_port = 50001;
  
  char *client_identity = "example_client";
  char *partner_identity = "example_daemon";
  
  char *key = "0123456789012345";
  
  ns_client_handler_t handler  = {
    .store_key = store_key,
    .get_key = get_key,
    .result = result
  };
  
  ns_get_key(handler,
        server_address, partner_address, 
        server_port, client_port, partner_port,
        client_identity, partner_identity, key);
  
  print_identities();
        
  return 0;
}