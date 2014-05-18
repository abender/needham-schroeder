#include "needham.h"

#include <errno.h>

int run = 1;

/* ---------------------------- Identity Storage --------------------------- */

typedef struct {
  UT_hash_handle hh;
  char name[NS_IDENTITY_LEN];
  char key[NS_KEY_LEN];
} identity_t;

identity_t *identities = NULL;

int store_key(char *identity_name, char *key) {
  identity_t *id;
  id = malloc(sizeof(identity_t));
  memset(id, 0, sizeof(identity_t));
  
  memcpy(id->name, identity_name, NS_IDENTITY_LEN);
  memcpy(id->key, key, NS_KEY_LEN);
  
  HASH_ADD_STR(identities, name, id);
  return 0;
}

int get_key(char *identity_name, char *key) {
  
  identity_t *id = NULL;
  HASH_FIND_STR(identities, identity_name, id);

  if(id) {
    memcpy(key, id->key, NS_KEY_LEN);
    return 0;
  } else {
    return -1;
  }
}

/* ----------------------------- Event Handling ---------------------------- */

int event(int code) {
  printf("needham-schroeder finished its negotiation with exit code %s.\n",
        ns_state_to_str(code));
  run = 0;
  return 0;
}

/* ---------------------------- Network Handlers --------------------------- */

int send_to_peer(struct ns_context_t *context, ns_abstract_address_t *addr,
      uint8_t *data, size_t len) {

  return sendto( *((int*) context->app), data, len, MSG_DONTWAIT, &addr->addr.sa, addr->size);
}

/* ---------------------------------- Util --------------------------------- */

void print_identities() {
  identity_t *id = NULL;
  int i = 0;
  char tmp_key[NS_KEY_LEN + 1] = { 0 };
  if(identities) {
    for(id = identities; id != NULL; id = id->hh.next) {
      memcpy(tmp_key, id->key, NS_KEY_LEN);
      printf("%d - name : %s, key : %s\n", i, id->name, tmp_key);
      i++;
    }
  } else {
    printf("- no identities stored -\n");
  }
}

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
  
  ns_context_t *context;
  int fd, read_bytes;
  char in_buffer[NS_CLIENT_BUFFER_SIZE];
  
  ns_abstract_address_t tmp_addr;
  memset(&tmp_addr, 0, sizeof(ns_abstract_address_t));
  tmp_addr.size = sizeof(tmp_addr.addr);
  
  fd_set rfds;
  struct timeval timeout;
  int sres = 0;
  
  char *server_address = "::1";
  char *partner_address = "::1";
  
  int server_port = 50000;
  int partner_port = 50010;
  int client_port = 50001;
  
  char *client_identity = "example_client";
  char *partner_identity = "example_daemon";
  
  char *key = "0123456789012345";
  
  ns_handler_t handler  = {
    .read = NULL,
    .write = send_to_peer,
    .store_key = store_key,
    .get_key = get_key,
    .event = event
  };
  
  fd = ns_bind_socket(client_port, AF_INET6);
  if(fd < 0)
    exit(-1);
  
  context = ns_initialize_context(&fd, &handler);
  if(!context) {
    ns_log_fatal("could not create context.");
    exit(-1);
  }
  
  ns_set_credentials(context, client_identity, key);
  
  ns_set_role(context, NS_ROLE_CLIENT);
  
  /* Here the key retrieval process starts */
  
  ns_log_info("server: %s, %d | partner: %s, %d, %s", server_address,
        server_port, partner_address, partner_port, partner_identity);
  
  ns_get_key(context, server_address, server_port, partner_address, partner_port,
        partner_identity);
  
  while(context->state < NS_STATE_FINISHED && run == 1) {
    
    FD_ZERO(&rfds);
    FD_SET(*((int*) context->app), &rfds);          
    timeout.tv_sec = NS_RETRANSMIT_TIMEOUT;
    timeout.tv_usec = 0;
    
    sres = select((*((int*) context->app))+1, &rfds, 0, 0, &timeout);
    
    if(sres < 0) {
      ns_log_warning("error while waiting for incoming packets: %s", strerror(errno));
    
    /* timeout */
    } else if(sres == 0) {
      ns_retransmit(context);
      
    /* new packet arrived, handle it */
    } else {
      read_bytes = recvfrom(fd, in_buffer, sizeof(in_buffer), 0, &tmp_addr.addr.sa, &tmp_addr.size);
      ns_handle_message(context, &tmp_addr, in_buffer, read_bytes);
    }
  }
  
  if(context->state == NS_STATE_FINISHED) {
    ns_log_info("successfully finished key negotiation.");
  } else {
    ns_log_error("an error occured while negotiating the key: %s", ns_state_to_str(context->state));
  }
  
  /* Key process completed, either on success or any error */
  
  print_identities();
  ns_destroy_context(context);
        
  return 0;
}