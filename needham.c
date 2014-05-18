/**
 * simple extended Needham-Schroeder implementation
 *
 * Copyright (c) 2013-2014 Andreas Bender <bender86@arcor.de>
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

#include "needham.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#ifndef CONTIKI
#include <sys/socket.h>
#include <netdb.h>
#endif /* CONTIKI */

#include "rin_wrapper.h"
#include "sha2/sha2.h"

#include "ccm.h"

#ifdef CONTIKI
/* Storage for peers */
MEMB(ns_peers_store, ns_peer_t, NS_MAX_PEERS);

/* Storage for context */
MEMB(ns_context_store, ns_context_t, 1);

/* Storage for outgoing messages, used for retransmissions. Needs 1 slot per peer */
MEMB(ns_out_buf_store, ns_out_item_t, NS_MAX_PEERS);

/* Storage for incoming messages, used for key responses that don't come in order.
   Needs 1 slot per peer */
MEMB(ns_in_buf_store, ns_in_item_t, NS_MAX_PEERS);
#endif /* CONTIKI */

/* Common functions */

void ns_alter_nonce(char *original, char *altered);

int ns_verify_nonce(char *original_nonce, char *verify_nonce);

#ifndef CONTIKI
int ns_resolve_sockaddr(char *server, struct sockaddr *dst);

int ns_resolve_address(char *address, int port, ns_abstract_address_t *resolved);
#endif /* CONTIKI */

char* ns_state_to_str(int state);

/* Protocol functions */

#ifndef CONTIKI // FIXME: check if function is still used
void ns_get_key(ns_context_t *context, char *server_address, int server_port,
      char *partner_address, int partner_port, char *partner_identity);
#endif /* CONTIKI */

void ns_handle_message(ns_context_t *context, ns_abstract_address_t *addr,
      char *buf, size_t len);
      
void ns_send_buffered(ns_context_t *context, ns_peer_t *peer, uint8_t *data, size_t len);

void ns_send_key_request(ns_context_t *context, ns_peer_t *server, ns_peer_t *peer);

void ns_handle_key_request(ns_context_t *context, ns_peer_t *peer,
      char *in_buffer, size_t len);

void ns_handle_key_response(ns_context_t *context, ns_peer_t *server,
      char *packet, size_t len);

void ns_send_com_request(ns_context_t *context, ns_peer_t *partner, char *packet);

void ns_handle_com_request(ns_context_t *context, ns_peer_t *peer,
      char *in_buffer, size_t len);

void ns_send_com_challenge(ns_context_t *context, ns_peer_t *peer);

void ns_handle_com_challenge(ns_context_t *context, ns_peer_t *peer,
      char *in_buffer, size_t len);

void ns_send_com_response(ns_context_t *context, ns_peer_t *peer, char *nonce);

void ns_handle_com_response(ns_context_t *context, ns_peer_t *peer,
      char *in_buffer, size_t len);

void ns_send_com_confirm(ns_context_t *context, ns_peer_t *peer);

void ns_handle_com_confirm(ns_context_t *context, ns_peer_t *peer,
      char *packet, size_t len);

void ns_handle_err_unknown_id(ns_context_t *context);

void ns_retransmit(ns_context_t *context);

void ns_reset_buffer(ns_peer_t *peer);

static inline ns_out_item_t* ns_alloc_out_item();

static inline void ns_free_out_item(ns_out_item_t *item);

static inline ns_peer_t* ns_alloc_peer();

static inline void ns_free_peer(ns_peer_t *peer);

ns_peer_t* ns_find_or_create_peer(ns_context_t *context,
      ns_abstract_address_t *peer_addr);
  
ns_peer_t* ns_find_peer_by_address(ns_context_t *context, ns_abstract_address_t *addr);
  
void ns_add_peer(ns_context_t *context, ns_peer_t *peer);
  
int ns_address_is_equal(ns_abstract_address_t *addr1, ns_abstract_address_t *addr2);
  
ns_peer_t* ns_find_peer_by_identity(ns_context_t *context, char *identity);

void ns_reset_peer(ns_peer_t *peer);

void ns_cleanup(ns_context_t *context);

void ns_create_timestamp(char* timestamp);

int ns_validate_timestamp(char* timestamp);

int ns_discard_invalid_messages(ns_context_t *context, char *buf, size_t len);

void ns_set_credentials(ns_context_t *context, char *identity, char *key);

static inline ns_context_t* ns_alloc_context();

static inline void ns_free_context(ns_context_t *ctx);

ns_context_t* ns_initialize_context(void *app, ns_handler_t *handler);

void ns_destroy_context(ns_context_t *context);

void ns_free_peers(ns_context_t *context);

uint64_t htonll(uint64_t val);

uint64_t ntohll(uint64_t val);

/* -------------------------------- #0 Common ------------------------------ */

void ns_alter_nonce(char *original, char *altered) {
  
#ifdef NS_DEBUG
  if(NS_NONCE_LEN > SHA256_BLOCK_LENGTH) {
    ns_log_warning("the nonce length (%d) is bigger than the provided hash buffer (%d)",
          NS_NONCE_LEN, SHA256_BLOCK_LENGTH);
  }
  if(NS_NONCE_LEN > SHA256_DIGEST_LENGTH) {
    ns_log_warning("the nonce length (%d) is bigger than the sha256 digest (%d)",
          NS_NONCE_LEN, SHA256_DIGEST_LENGTH);
  }
#endif
  
  char buf[SHA256_DIGEST_LENGTH] = { 0 };

  memcpy(buf, original, NS_NONCE_LEN);
  
	SHA256_CTX	ctx256;
	SHA256_Init(&ctx256);
	SHA256_Update(&ctx256, (unsigned char*) buf, NS_NONCE_LEN);
  SHA256_Final((uint8_t*) buf, &ctx256);
	
  memcpy(altered, buf, NS_NONCE_LEN);
}

int ns_verify_nonce(char *original_nonce, char *verify_nonce) {
  
  char altered_nonce[NS_NONCE_LEN];
  ns_alter_nonce(original_nonce, altered_nonce);
  
  if(memcmp(altered_nonce, verify_nonce, NS_NONCE_LEN) == 0) {
    return 0;
  } else {
#ifdef NS_DEBUG
    ns_log_debug("--------------------");
    ns_log_debug("nonce verification failed, my altered nonce is:");
    ns_dump_bytes_to_hex((unsigned char*) altered_nonce, NS_NONCE_LEN);
    ns_log_debug("but the received nonce is:");
    ns_dump_bytes_to_hex((unsigned char*) verify_nonce, NS_NONCE_LEN);
    ns_log_debug("--------------------");
#endif
    return -1;
  }
}

#ifndef CONTIKI
/* Taken from libcoap by Olaf Bergmann: http://libcoap.sourceforge.net */
int ns_resolve_sockaddr(char *server, struct sockaddr *dst) {
  
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error, len=-1;

  memset(addrstr, 0, sizeof(addrstr));
  if (strlen(server))
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:
      len = ainfo->ai_addrlen;
      memcpy(dst, ainfo->ai_addr, len);
      goto finish;
    default:
      ;
    }
  }

 finish:
  freeaddrinfo(res);
  return len;
}

int ns_resolve_address(char *address, int port, ns_abstract_address_t *resolved) {
  
  int res;
  res = ns_resolve_sockaddr(address, &(resolved->addr.sa));
  
  if(res < 0) {
    ns_log_error("Failed to resolve address\n");
    return -1;
  }
  
  resolved->size = res;
  resolved->addr.sin.sin_port = htons(port);
  
  return res;
}
#if 0
/* Slightly modified version of resolve_address from libtinydtls by Olaf Bergmann
 ( MIT License: http://tinydtls.sourceforge.net/)  */
int
ns_resolve_address(char *address, int port, ns_abstract_address_t *resolved) {
  
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;

  memset(addrstr, 0, sizeof(addrstr));
  if (address && strlen(address) > 0)
    memcpy(addrstr, address, strlen(address));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    ns_log_fatal("getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
    case AF_INET6:
      inet_pton(AF_INET6, address, &(resolved->addr.sin6.sin6_addr));
      resolved->addr.sin6.sin6_port = htons(port);
      resolved->size = ainfo->ai_addrlen;
      return ainfo->ai_addrlen;
    /* TODO implement */
    case AF_INET:
      memcpy(&resolved->addr, ainfo->ai_addr, ainfo->ai_addrlen);
      resolved->addr.sin.sin_port = htons(port);
      resolved->size = ainfo->ai_addrlen;
      return ainfo->ai_addrlen;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return -1;

}
#endif

#endif /* CONTIKI */

#ifndef CONTIKI
/**
 * Creates and binds an IPv6 UDP socket and returns its fd.
 */
int ns_bind_socket(int port, unsigned char family) {
  
  int s;
  int on = 1;
  int off = 0;
  s = socket(family, SOCK_DGRAM, 0);
  
  if(s < 0) {
    ns_log_fatal("Could not create socket: %s", strerror(errno));
    return -1;
  }
  
  if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    ns_log_warning("setsockopt SO_REUSEADDR");
    
  if(family == AF_INET6) {
    if(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)) < 0)
      ns_log_warning("setsockopt IPV6_V6ONLY\n");
  }
  
  if(family == AF_INET6) {
    
    struct sockaddr_in6 listen_addr;

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin6_family = AF_INET6;
    listen_addr.sin6_port = htons(port);
    listen_addr.sin6_addr = in6addr_any;

    if(bind(s, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
      ns_log_fatal("Could not bind socket: %s", strerror(errno));
      return -1;
    }
    
  } else if(family == AF_INET) {
    
    struct sockaddr_in listen_addr;
    
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(port);
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(s, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
      ns_log_fatal("Could not bind socket: %s", strerror(errno));
      return -1;
    }
    
  } else {
    ns_log_fatal("unkown address family: %s", family);
    return -1;
  }
  return s;
}
#endif /* CONTIKI */

char* ns_state_to_str(int state) {
  switch(state) {
    case NS_STATE_INITIAL: return "NS_STATE_INITIAL"; break;
    case NS_STATE_KEY_REQUEST: return "NS_STATE_KEY_REQUEST"; break;
    case NS_STATE_KEY_RESPONSE: return "NS_STATE_KEY_RESPONSE"; break;
    case NS_STATE_COM_REQUEST: return "NS_STATE_COM_REQUEST"; break;
    case NS_STATE_COM_CHALLENGE: return "NS_STATE_COM_CHALLENGE"; break;
    case NS_STATE_COM_RESPONSE: return "NS_STATE_COM_RESPONSE"; break;
    case NS_STATE_COM_CONFIRM: return "NS_STATE_COM_CONFIRM"; break;
    case NS_STATE_FINISHED: return "NS_STATE_FINISHED"; break;
    case NS_ERR_UNKNOWN_ID: return "NS_ERR_UNKNOWN_ID"; break;
    case NS_ERR_REJECTED: return "NS_ERR_REJECTED"; break;
    case NS_ERR_NONCE: return "NS_ERR_NONCE"; break;
    case NS_ERR_TIMEOUT: return "NS_ERR_TIMEOUT"; break;
    case NS_ERR_UNKNOWN: return "NS_ERR_UNKNOWN"; break;
    default: return "undefined"; break;
  }
}

/* ------------------------------ #1 Protocol ------------------------------ */

#ifndef CONTIKI
void ns_get_key(ns_context_t *context, char *server_address, int server_port,
      char *partner_address, int partner_port, char *partner_identity) {
        
  ns_abstract_address_t server_addr, partner_addr;
  ns_peer_t *server, *partner;
  
  memset(&server_addr, 0, sizeof(ns_abstract_address_t));
  memset(&partner_addr, 0, sizeof(ns_abstract_address_t));
  
  ns_resolve_address(server_address, server_port, &server_addr);
  ns_resolve_address(partner_address, partner_port, &partner_addr);
  
  server = ns_find_or_create_peer(context, &server_addr);
  partner = ns_find_or_create_peer(context, &partner_addr);
  
  memcpy(partner->identity, partner_identity, NS_IDENTITY_LEN);
  
  ns_send_key_request(context, server, partner);
}
#endif /* CONTIKI */

void ns_handle_message(ns_context_t *context, ns_abstract_address_t *addr,
      char *buf, size_t len) {

  /* clean up marked peers */
  ns_cleanup(context);

  ns_peer_t *peer;
  peer = ns_find_or_create_peer(context, addr);
  
  if(!peer) {
    ns_log_warning("no peer available to handle this request, discarding it.");
    return;
  }

  if(ns_discard_invalid_messages(context, buf, len) < 0)
    return;
  
  char code = buf[0];

  /* No switch-case because of Contiki Threads */
  if(code == NS_STATE_KEY_REQUEST) {
    ns_handle_key_request(context, peer, buf, len);
  } else if(code == NS_STATE_KEY_RESPONSE) {
    ns_handle_key_response(context, peer, buf, len);
  } else if(code == NS_STATE_COM_REQUEST) {
    ns_handle_com_request(context, peer, buf, len);
  } else if(code == NS_STATE_COM_CHALLENGE) {
    ns_handle_com_challenge(context, peer, buf, len);
  } else if(code == NS_STATE_COM_RESPONSE) {
    ns_handle_com_response(context, peer, buf, len);
  } else if(code == NS_STATE_COM_CONFIRM) {
    ns_handle_com_confirm(context, peer, buf, len);
  } else if(code == NS_ERR_UNKNOWN_ID) {
    ns_handle_err_unknown_id(context);
  } else {
    ns_log_warning("this shouldn't be reached at all because of ns_discard_invalid_messages");
    context->state = NS_ERR_UNKNOWN;
    context->handler->event(context->state);
  }
}

void ns_send_buffered(ns_context_t *context, ns_peer_t *peer, uint8_t *data, size_t len) {

  /* clear previously buffered messages */
  if(peer->out_buf)
    ns_free_out_item(peer->out_buf);

  peer->out_buf = ns_alloc_out_item();
  if(!peer->out_buf) {
	ns_log_warning("no memory to buffer message!");
	return;
  }

  /* store this packet for possible retransmissions */
  peer->out_buf->len = len;
  peer->out_buf->retransmits = 0;
  memcpy(peer->out_buf->data, data, len);

  context->handler->write(context, &peer->addr, data, len);
}

void ns_send_key_request(ns_context_t *context, ns_peer_t *server, ns_peer_t *peer) {
  
  ns_random_nonce(server->nonce, NS_NONCE_LEN);
  
  /* Message Code + Client identity + Partner identity + Nonce */
  char out_buffer[NS_KEY_REQUEST_LEN] = { 0 };
  
  out_buffer[0] = NS_STATE_KEY_REQUEST;
  
  int pos = 1;
  memcpy(&out_buffer[pos], context->identity, strnlen(context->identity, NS_IDENTITY_LEN));
  pos += NS_IDENTITY_LEN;
  memcpy(&out_buffer[pos], peer->identity,
        strnlen(peer->identity, NS_IDENTITY_LEN));
  pos += NS_IDENTITY_LEN;
  memcpy(&out_buffer[pos], server->nonce, NS_NONCE_LEN);
  
  ns_send_buffered(context, server, (uint8_t*) out_buffer, sizeof(out_buffer));

  context->state = NS_STATE_KEY_REQUEST;

  ns_log_info("sent key request to server.");

}

/*
 * Handle a key request from \p peer. The packet is stored in \p in_buffer with
 * length \p len.
 */
void ns_handle_key_request(ns_context_t *context, ns_peer_t *peer,
       char *in_buffer, size_t len) {
  
  int get_sender, get_receiver;
  
  char id_sender[NS_IDENTITY_LEN+1] = { 0 };
  char id_receiver[NS_IDENTITY_LEN+1] = { 0 };
  char key_sender[NS_RIN_KEY_LEN+1] = { 0 };
  char key_receiver[NS_RIN_KEY_LEN+1] = { 0 };
  char nonce[NS_NONCE_LEN+1] = { 0 };
  
  memset(id_sender, 0, sizeof(id_sender));
  memset(id_receiver, 0, sizeof(id_receiver));
  memset(nonce, 0, sizeof(nonce));
  
  /* Get values from incoming packet (sender, receiver, nonce) */
  int pos = 1;
  memcpy(&id_sender, &in_buffer[1], NS_IDENTITY_LEN);
  pos += NS_IDENTITY_LEN;
  memcpy(&id_receiver, &in_buffer[pos], NS_IDENTITY_LEN);
  pos += NS_IDENTITY_LEN;
  memcpy(&nonce, &in_buffer[pos], NS_NONCE_LEN);
  
  ns_log_info("Received STATE_KEY_REQUEST (Sender-ID: %s, Receiver-ID: %s).",
      id_sender, id_receiver);
  
  get_sender = context->handler->get_key(id_sender, key_sender);
  get_receiver = context->handler->get_key(id_receiver, key_receiver);
  
  /* Identity not found, send ERR_UNKNOWN_ID */
  if(get_sender == -1 || get_receiver == -1) {
    char out_buffer[1];
    out_buffer[0] = NS_ERR_UNKNOWN_ID;    
    ns_log_info("Sent error NS_ERR_UNKNOWN_ID.");
    
    context->handler->write(context, &peer->addr, (uint8_t*) out_buffer, sizeof(out_buffer));
  
  /* Identities found, construct and send the response containing the session ticket */
  } else {
	
	  /* create session key */
    char session_key[NS_KEY_LEN];
    ns_random_key(session_key, NS_KEY_LEN);

    /* Build and encrypt the ticket */
    char ticket_buf[NS_TICKET_LEN] = { 0 };
    char ticket_nonce[DTLS_CCM_BLOCKSIZE] = { 0 }; 
    ns_random_nonce(ticket_nonce, NS_CCM_N);

      /* Build ticket for encryption: ( CCM Nonce, Key, ID, T ) */
    memcpy(ticket_buf, ticket_nonce, NS_CCM_N);
    pos = NS_CCM_N;
    memcpy(&ticket_buf[pos], session_key, NS_KEY_LEN);
    pos += NS_KEY_LEN;
    memcpy(&ticket_buf[pos], id_sender, NS_IDENTITY_LEN);
    pos += NS_IDENTITY_LEN;
    ns_create_timestamp(&ticket_buf[pos]);

    /* Prepare encryption. The ticket will be encrypted using the receivers key */
    rijndael_ctx ctx;
    if(rijndael_set_key_enc_only(&ctx, (u_char*) key_receiver, 8 * NS_RIN_KEY_LEN) < 0) {
    	ns_log_warning("unable to set key for Rijndael context (ticket encryption)");
    	return;
    }

    dtls_ccm_encrypt_message(&ctx, NS_CCM_M, NS_CCM_L, (u_char*) ticket_nonce,
      (u_char*) &ticket_buf[NS_CCM_N], NS_KEY_LEN + NS_IDENTITY_LEN + NS_TIMESTAMP_LEN,
      NULL, 0);
    /* TODO: Any way to check if the encryption was successful? */


    /* Now we build the full message, containing the previously built ticket. */
    char response_buf[NS_KEY_RESPONSE_LEN] = { 0 };

    char response_nonce[DTLS_CCM_BLOCKSIZE] = { 0 };
    ns_random_nonce(response_nonce, NS_CCM_N);

      /* Prepare the response for encryption:
         Code, CCM Nonce, NS Nonce, ID, Key, Ticket */
    response_buf[0] = NS_STATE_KEY_RESPONSE;
    pos = 1;
    memcpy(&response_buf[pos], response_nonce, NS_CCM_N);
    pos += NS_CCM_N;
    ns_alter_nonce(nonce, &response_buf[pos]); /* include altered nonce in response */
    pos += NS_NONCE_LEN;
    memcpy(&response_buf[pos], id_receiver, NS_IDENTITY_LEN);
    pos += NS_IDENTITY_LEN;
    memcpy(&response_buf[pos], session_key, NS_KEY_LEN);
    pos += NS_KEY_LEN;
    memcpy(&response_buf[pos], ticket_buf, NS_TICKET_LEN);

    if(rijndael_set_key_enc_only(&ctx, (u_char*) key_sender, 8 * NS_RIN_KEY_LEN) < 0) {
    	ns_log_warning("unable to set key for Rijndael context (response encryption)");
    	return;
    }
    
    dtls_ccm_encrypt_message(&ctx, NS_CCM_M, NS_CCM_L, (u_char*) response_nonce,
        (u_char*) &response_buf[1 + NS_CCM_N], /* Starting point is behind the CCM Nonce */
      NS_NONCE_LEN + NS_IDENTITY_LEN + NS_KEY_LEN + NS_TICKET_LEN,
      NULL, 0);
    /* TODO: Any way to check if the encryption was successful? */

    context->handler->write(context, &peer->addr, (uint8_t*) response_buf,
      sizeof(response_buf));

    ns_log_info("Sent key response.");
  }
}

void ns_handle_key_response(ns_context_t *context, ns_peer_t *server,
       char *packet, size_t len) {
  
  /* Stop retransmissions
     FIXME: Only stop retransmissions if the following process is successul? */
  ns_reset_buffer(server);

  /* Decrypt the outer layer of the response */
  rijndael_ctx ctx;
  if(rijndael_set_key_enc_only(&ctx, (u_char*) context->key, 8 * NS_RIN_KEY_LEN) < 0) {
    ns_log_error("unable to initiate Rijndael context.");
    return;
  }
  
  /* take the nonce for CCM from the incoming packet */
  char ccm_nonce[DTLS_CCM_BLOCKSIZE];
  memcpy(ccm_nonce, &packet[1], NS_CCM_N);

  if(dtls_ccm_decrypt_message(&ctx, NS_CCM_M, NS_CCM_L, (u_char*) ccm_nonce,
     (u_char*) &packet[1 + NS_CCM_N], NS_KEY_RESPONSE_LEN - 1 - NS_CCM_N,
     NULL, 0) <= 0) {
    /* TODO: Error handling of decryption errors */
    ns_log_warning("error while decrypting message");	
    return;
  }
  
  /* get and verify the received nonce */
  char altered_nonce[NS_NONCE_LEN];
  memcpy(altered_nonce, &packet[1 + NS_CCM_N], NS_NONCE_LEN);

  /* Check if I know the partners identity, discard the message if the partner
     is unknown */
  char partner_identity[NS_IDENTITY_LEN] = { 0 };
  memcpy(partner_identity, &packet[1 + NS_CCM_N + NS_NONCE_LEN], NS_IDENTITY_LEN);
  ns_peer_t *partner;
  partner = ns_find_peer_by_identity(context, partner_identity);
  if(!partner) {
    ns_log_warning("key response with unknown partner identity, discarding packet");
    return;
  }

  /* don't handle this packet if the received nonce is wrong */
  if(ns_verify_nonce(server->nonce, altered_nonce) != 0) {
    ns_log_warning("nonce verification failed!");
    context->state = NS_ERR_NONCE;
    return;
  }

  /* If the partner is known and we received the correct nonce we can store the
     session key temporarily. (It will be stored via callback later, if the
     challenge-response succeeds) */
  memcpy(partner->key, &packet[1 + NS_CCM_N + NS_NONCE_LEN + NS_IDENTITY_LEN],
    NS_KEY_LEN);

  context->state = NS_STATE_KEY_RESPONSE;

  ns_send_com_request(context, partner, &packet[1 + NS_CCM_N + NS_NONCE_LEN +
    NS_IDENTITY_LEN + NS_KEY_LEN]);
}

void ns_send_com_request(ns_context_t *context, ns_peer_t *partner, char *packet) {
  
  char out_buffer[NS_COM_REQ_LEN];
  
  out_buffer[0] = NS_STATE_COM_REQUEST;
  memcpy(&out_buffer[1], packet, NS_TICKET_LEN);
  
  ns_send_buffered(context, partner, (uint8_t*) out_buffer, sizeof(out_buffer));
  
  context->state = NS_STATE_COM_REQUEST;
  ns_log_debug("sent com request to peer.");
}

void ns_handle_com_request(ns_context_t *context, ns_peer_t *peer,
      char *in_buffer, size_t len) {

  rijndael_ctx ctx;
  if(rijndael_set_key_enc_only(&ctx, (u_char*) context->key, 8 * NS_RIN_KEY_LEN) < 0) {
    ns_log_error("unable to initiate Rijndael context.");
    return;
  }

  /* get the CCM nonce from the received packet */
  char ccm_nonce[DTLS_CCM_BLOCKSIZE] = { 0 };
  memcpy(ccm_nonce, &in_buffer[1], NS_CCM_N);

  if(dtls_ccm_decrypt_message(&ctx, NS_CCM_M, NS_CCM_L, (u_char*) ccm_nonce,
    (u_char*) &in_buffer[1 + NS_CCM_N], NS_TICKET_LEN - NS_CCM_N,
    NULL, 0) <= 0) {
    /* TODO: Error handling of decryption errors */
    ns_log_warning("error while decrypting message");	
    return;
  }
    
  /* Temporarily remember the clients credentials, they will be stored via
     callback when the nonce verification succeeded */
  int pos = 1 + NS_CCM_N;
  memcpy(peer->key, &in_buffer[pos], NS_KEY_LEN);
  pos += NS_KEY_LEN;
  memcpy(peer->identity, &in_buffer[pos], NS_IDENTITY_LEN);
  pos += NS_IDENTITY_LEN;
  
  /* Validate time. Don't handle this packet if validation fails */
  if(ns_validate_timestamp(&in_buffer[pos]) != 0) {
    ns_log_warning("received packet with expired timestamp, discarding it."
      " (this may also be caused by a wrong key for decryption)");
    return;
  }
  
#ifdef NS_DEBUG
  // FIXME shorter way to print these as strings?
  char d_key[NS_KEY_LEN+1] = { 0 };
  char d_identity[NS_IDENTITY_LEN+1] = { 0 };
  memcpy(d_key, peer->key, NS_KEY_LEN);
  memcpy(d_identity, peer->identity, NS_IDENTITY_LEN);
  ns_log_debug("received com request. ( Sender-ID: %s, Key: %s )", d_identity, d_key);
#endif
  
  ns_send_com_challenge(context, peer);
}

void ns_send_com_challenge(ns_context_t *context, ns_peer_t *peer) {
  
  char out_buffer[NS_COM_CHALLENGE_LEN] = { 0 };

  out_buffer[0] = NS_STATE_COM_CHALLENGE;

  /* create the challenge-response nonce */
  ns_random_nonce(peer->nonce, NS_NONCE_LEN);
  memcpy(&out_buffer[1 + NS_CCM_N], peer->nonce, NS_NONCE_LEN);
  
  /* create the nonce used by CCM */
  char ccm_nonce[DTLS_CCM_BLOCKSIZE] = { 0 };
  ns_random_nonce(ccm_nonce, NS_CCM_N);
  memcpy(&out_buffer[1], ccm_nonce, NS_CCM_N);
  
  rijndael_ctx ctx;
  if(rijndael_set_key_enc_only(&ctx, (u_char*) peer->key, 8 * NS_RIN_KEY_LEN) < 0) {
  	ns_log_warning("unable to set key");
  	return;
  }
  
  dtls_ccm_encrypt_message(&ctx, NS_CCM_M, NS_CCM_L, (u_char*) ccm_nonce,
      (u_char*) &out_buffer[1 + NS_CCM_N], /* Starting point is behind the CCM Nonce */
    NS_NONCE_LEN,
    NULL, 0);
  /* TODO: Any way to check if the encryption was successful? */
  
  context->handler->write(context, &peer->addr, (uint8_t*) out_buffer, sizeof(out_buffer));
  
  peer->state = NS_STATE_COM_CHALLENGE;
  ns_log_debug("Sent com challenge to peer.");
}

void ns_handle_com_challenge(ns_context_t *context, ns_peer_t *peer,
       char *in_buffer, size_t len) {
  
  /* stop retransmission */
  ns_reset_buffer(peer);
  
  ns_log_debug("received com challenge");
  context->state = NS_STATE_COM_CHALLENGE;
  
  rijndael_ctx ctx;
  if(rijndael_set_key_enc_only(&ctx, (u_char*) peer->key, 8 * NS_RIN_KEY_LEN) < 0) {
    ns_log_error("unable to initiate Rijndael context.");
    return;
  }

  /* get the CCM nonce from the received packet */
  char ccm_nonce[DTLS_CCM_BLOCKSIZE] = { 0 };
  memcpy(ccm_nonce, &in_buffer[1], NS_CCM_N);

  if(dtls_ccm_decrypt_message(&ctx, NS_CCM_M, NS_CCM_L, (u_char*) ccm_nonce,
    (u_char*) &in_buffer[1 + NS_CCM_N], NS_NONCE_LEN + NS_CCM_M,
    NULL, 0) <= 0) {
    /* TODO: Error handling of decryption errors */
    ns_log_warning("error while decrypting message");	
    return;
  }
  
  char altered_nonce[NS_NONCE_LEN] = { 0 };
  ns_alter_nonce(&in_buffer[1 + NS_CCM_N], altered_nonce);

  ns_send_com_response(context, peer, altered_nonce);
}

void ns_send_com_response(ns_context_t *context, ns_peer_t *peer, char *nonce) {
  
  char out_buffer[NS_COM_RESPONSE_LEN] = { 0 };
  out_buffer[0] = NS_STATE_COM_RESPONSE;
  
  /* copy the altered nonce to the buffer, it will be encrypted in place */
  memcpy(&out_buffer[1 + NS_CCM_N], nonce, NS_NONCE_LEN);
  
  /* create the nonce used by CCM */
  char ccm_nonce[DTLS_CCM_BLOCKSIZE] = { 0 };
  ns_random_nonce(ccm_nonce, NS_CCM_N);
  memcpy(&out_buffer[1], ccm_nonce, NS_CCM_N);
  
  rijndael_ctx ctx;
  if(rijndael_set_key_enc_only(&ctx, (u_char*) peer->key, 8 * NS_RIN_KEY_LEN) < 0) {
  	ns_log_warning("unable to set key");
  	return;
  }
  
  dtls_ccm_encrypt_message(&ctx, NS_CCM_M, NS_CCM_L, (u_char*) ccm_nonce,
      (u_char*) &out_buffer[1 + NS_CCM_N], /* Starting point is behind the CCM Nonce */
    NS_NONCE_LEN,
    NULL, 0);
  /* TODO: Any way to check if the encryption was successful? */
      
  ns_send_buffered(context, peer, (uint8_t*) out_buffer, sizeof(out_buffer));
  
  context->state = NS_STATE_COM_RESPONSE;
  ns_log_debug("sent com response");
}

void ns_handle_com_response(ns_context_t *context, ns_peer_t *peer,
      char *in_buffer, size_t len) {

  rijndael_ctx ctx;
  if(rijndael_set_key_enc_only(&ctx, (u_char*) peer->key, 8 * NS_RIN_KEY_LEN) < 0) {
    ns_log_error("unable to initiate Rijndael context.");
    return;
  }

  /* get the CCM nonce from the received packet */
  char ccm_nonce[DTLS_CCM_BLOCKSIZE] = { 0 };
  memcpy(ccm_nonce, &in_buffer[1], NS_CCM_N);

  if(dtls_ccm_decrypt_message(&ctx, NS_CCM_M, NS_CCM_L, (u_char*) ccm_nonce,
    (u_char*) &in_buffer[1 + NS_CCM_N], NS_NONCE_LEN + NS_CCM_M,
    NULL, 0) <= 0) {
    /* TODO: Error handling of decryption errors */
    ns_log_warning("error while decrypting message");	
    return;
  }
  
  /* only store the key if the nonce verification succeded. otherwise the peer
     will be deleted without storing any credentials */
  if(ns_verify_nonce(peer->nonce, &in_buffer[1 + NS_CCM_N]) == 0) {
    context->handler->store_key(peer->identity, peer->key);
    ns_send_com_confirm(context, peer);
    ns_log_info("completed ns-handshake and stored new key.");
  } else {
    ns_log_info("nonce verification failed");
  }

  /* Mark this peer as completed. If the client receives the com confirm message
     it won't send any further messages and the peer can be cleaned up after
     this timeout. */
#ifndef CONTIKI
  peer->expires = time(NULL) + (NS_RETRANSMIT_TIMEOUT * NS_RETRANSMIT_MAX * 2);
#else
  peer->expires = clock_seconds() + (NS_RETRANSMIT_TIMEOUT * NS_RETRANSMIT_MAX * 2);
#endif /* CONTIKI */
}

void ns_send_com_confirm(ns_context_t *context, ns_peer_t *peer) {
  
  char out_buffer[1];
  out_buffer[0] = NS_STATE_COM_CONFIRM;

  context->handler->write(context, &peer->addr, (uint8_t*) out_buffer, sizeof(out_buffer));
  peer->state = NS_STATE_COM_CONFIRM;
  ns_log_debug("sent confirmation message.");
}

void ns_handle_com_confirm(ns_context_t *context, ns_peer_t *peer,
       char *packet, size_t len) {
  
  ns_reset_buffer(peer);
  
  context->handler->store_key(peer->identity, peer->key);
  context->state = NS_STATE_FINISHED;
  ns_log_info("received com confirm. process completed.");
}

void ns_handle_err_unknown_id(ns_context_t *context) {
  
  context->state = NS_ERR_UNKNOWN_ID;
  ns_log_info("the server doesn't know the used id(s)");
  context->handler->event(context->state);
}

void ns_retransmit(ns_context_t *context) {

  ns_peer_t *p = NULL;

#ifdef CONTIKI
  for(p = list_head(context->peers); p; p = list_item_next(p)) {
#else /* CONTIKI */
  for(p = context->peers; p != NULL; p = p->hh.next) {
#endif /* CONTIKI */
    /* resend if there is anything buffered */
    if(p->out_buf != NULL) {
      if(p->out_buf->retransmits < NS_RETRANSMIT_MAX) {
        context->handler->write(context, &p->addr, p->out_buf->data, p->out_buf->len);
        p->out_buf->retransmits++;
#ifdef NS_DEBUG
        ns_log_info("retransmitted message [%d/%d]", p->out_buf->retransmits, NS_RETRANSMIT_MAX);
#endif
      /* max retransmittions reached */
      } else {
#ifdef NS_DEBUG
        ns_log_info("maximum retransmittions reached.");
#endif
        context->state = NS_ERR_TIMEOUT;
        context->handler->event(NS_ERR_TIMEOUT);
      }
    }
  }
}

void ns_reset_buffer(ns_peer_t *peer) {
  
  ns_free_out_item(peer->out_buf);
  peer->out_buf = NULL;
}

/* Methods to alloc/dealloc outgoing messages */
static inline ns_out_item_t*
ns_alloc_out_item() {
#ifdef CONTIKI
  return (ns_out_item_t*) memb_alloc(&ns_out_buf_store);
#else
  return (ns_out_item_t*) malloc(sizeof(ns_out_item_t));
#endif /* CONTIKI */
}

static inline void
ns_free_out_item(ns_out_item_t *item) {
#ifdef CONTIKI
  memb_free(&ns_out_buf_store, item);
#else
  free(item);
#endif /* CONTIKI */
}

/* Methods to alloc/dealloc peers */
static inline ns_peer_t*
ns_alloc_peer() {
#ifdef CONTIKI
  return (ns_peer_t*) memb_alloc(&ns_peers_store);
#else
  return (ns_peer_t*) malloc(sizeof(ns_peer_t));
#endif /* CONTIKI */
}

static inline void
ns_free_peer(ns_peer_t *peer) {
  ns_free_out_item(peer->out_buf);
#ifdef CONTIKI
  memb_free(&ns_peers_store, peer);
#else
  free(peer);
#endif /* CONTIKI */
}

/**
 * Finds or creates a daemon peer for the daemons context.
 *
 * @return A pointer to the found or created peer or NULL on any error (which
 *       propably will be not enough memory in constrained environments)
 */
ns_peer_t* ns_find_or_create_peer(ns_context_t *context,
      ns_abstract_address_t *peer_addr) {
  
  ns_peer_t *peer = NULL;
  
  peer = ns_find_peer_by_address(context, peer_addr);
  if(peer) {
    return peer;
  }
  
  /* peer doesn't exist, create and store a new one */
  peer = ns_alloc_peer();
  
  if(!peer) {
#ifdef NS_DEBUG
    ns_log_warning("no memory: alloc ns_peer_t");
#endif
    return peer;
  }
  
  /* ok, we have enough memory and a newly created peer, initialize it with data */
  memset(peer, 0, sizeof(ns_peer_t));
  memcpy(&peer->addr, peer_addr, sizeof(ns_abstract_address_t));
  peer->state = NS_STATE_INITIAL;
  
  ns_add_peer(context, peer);

#ifdef NS_DEBUG
  ns_log_debug("created new peer");
#endif

  return peer;
}

ns_peer_t* ns_find_peer_by_address(ns_context_t *context, ns_abstract_address_t *addr) {
  
  ns_peer_t *peer = NULL;
  
#ifndef CONTIKI
  HASH_FIND(hh, context->peers, addr, sizeof(ns_abstract_address_t), peer);
#else /* CONTIKI */
  for(peer = list_head(context->peers); peer; peer = list_item_next(peer)) {
    if(ns_address_is_equal(&peer->addr, addr)) break;
  }
#endif /* CONTIKI */

  return peer;
}

void ns_add_peer(ns_context_t *context, ns_peer_t *peer) {
#ifndef CONTIKI
  HASH_ADD(hh, context->peers, addr, sizeof(ns_abstract_address_t), peer);
#else /* CONTIKI */
  list_add(context->peers, peer);
#endif /* CONTIKI */
}

int ns_address_is_equal(ns_abstract_address_t *addr1, ns_abstract_address_t *addr2) {
#ifndef CONTIKI
  if(addr1->addr.sa.sa_family != addr2->addr.sa.sa_family)
    return 0;
    
  if(addr1->addr.sa.sa_family == AF_INET) {
    return (addr1->addr.sin.sin_port == addr2->addr.sin.sin_port &&
          memcmp(&addr1->addr.sin.sin_addr, &addr2->addr.sin.sin_addr,
          sizeof(struct in_addr)) == 0);
  } else if(addr1->addr.sa.sa_family == AF_INET6) {
    return (addr1->addr.sin6.sin6_port == addr2->addr.sin6.sin6_port &&
          memcmp(&addr1->addr.sin6.sin6_addr, &addr2->addr.sin6.sin6_addr,
          sizeof(struct in6_addr)) == 0);
  } else {
    return 0;
  }
  
#else /* CONTIKI */
  return (addr1->size == addr2->size && uip_ipaddr_cmp(&addr1->addr, &addr2->addr) &&
        addr1->port == addr2->port);
#endif /* CONTIKI */
}

/**
 * Searches for an existing peer with \p identity.
 *
 * @return A pointer to the found peer or NULL if none is found.
 */
ns_peer_t* ns_find_peer_by_identity(ns_context_t *context, char *identity) {
  
  ns_peer_t *p = NULL;

#ifndef CONTIKI
  for(p = context->peers; p != NULL; p = p->hh.next) {
    if(strncmp(p->identity, identity, strlen(identity)) == 0)
      return p;
  }
#else /* CONTIKI */
  for(p = list_head(context->peers); p; p = list_item_next(p)) {
    if(strncmp(p->identity, identity, strlen(identity)) == 0)
      return p;
  }
#endif /* CONTIKI */
  
  return p;
}

void ns_reset_peer(ns_peer_t *peer) {
  
  memset(peer->nonce, 0, NS_NONCE_LEN);
  memset(peer->identity, 0, NS_IDENTITY_LEN);
  memset(peer->key, 0, NS_KEY_LEN);
  peer->expires = 0;
  peer->state = NS_STATE_INITIAL;

  if(peer->out_buf)
	ns_free_out_item(peer->out_buf);
  peer->out_buf = NULL;

}

void ns_cleanup(ns_context_t *context) {
  
  ns_peer_t *peer;

 /* delete expired peers */

#ifdef CONTIKI
  for(peer = list_head(context->peers); peer; peer = list_item_next(peer)) {
    if(peer->expires != 0 && peer->expires < clock_seconds()) {
      list_remove(context->peers, peer);
      ns_free_peer(peer);
    }
  }
#else /* CONTIKI */
  ns_peer_t *tmp;
  HASH_ITER(hh, context->peers, peer, tmp) {
    if(peer->expires != 0 && peer->expires < time(NULL)) {
      HASH_DEL(context->peers, peer);
      ns_free_peer(peer);
    }
  }
#endif /* CONTIKI */
}

/**
 * Create a 8-bytes timestamp in network-byte-order
 */
void ns_create_timestamp(char* timestamp) {

  uint64_t now; /* big enough for every reasonable timestamp */
  
#ifndef CONTIKI
  time_t t;
  t = time(NULL);
#else
  unsigned long t;
  t = clock_seconds();
#endif /* CONTIKI */

  now = htonll((uint64_t) t);
  memcpy(timestamp, &now, sizeof(uint64_t));
}

/**
 * Validate a timestamp, which is stored where \p timestamp points at.
 * The timestamp should be a uint64_t in network-byte-order.
 */
int ns_validate_timestamp(char* timestamp) {

#ifdef CONTIKI
/* FIXME: timestamp validation disabled for contiki until I've found a way to
   validate timestamps for nodes without proper clock */
  return 0;
#endif

  /* get host-byte-order timestamp */
  uint64_t t = ntohll(*((uint64_t*) timestamp));
  
  uint64_t now;
#ifndef CONTIKI
  now = (uint64_t) time(NULL);
#else
  now = (uint64_t) clock_seconds();
#endif /* CONTIKI */

  if(now - t > NS_KEY_LIFETIME) {
#ifdef NS_DEBUG
    ns_log_debug("current time is: %llu, received timestamp: %llu. (now - t = %llu)\n",
      now, t, (now - t));
#endif
    return -1;
  } else {
    return 0;
  }
}

/**
 * Validates the message code and discards messages that don't fit the applications
 * role.
 */
int ns_discard_invalid_messages(ns_context_t *context, char *buf, size_t len) {
  
  char code = buf[0];
  ns_role_t role = context->role;
  
  if(role == NS_ROLE_CLIENT) {
    if(code == NS_STATE_KEY_RESPONSE || code == NS_STATE_COM_CHALLENGE ||
       code == NS_STATE_COM_CONFIRM || code == NS_ERR_UNKNOWN_ID ||
       code == NS_ERR_REJECTED || code == NS_ERR_NONCE)
       return 0;
    
  } else if(role == NS_ROLE_SERVER) {
    if(code == NS_STATE_KEY_REQUEST)
      return 0;
    
  } else if(role == NS_ROLE_DAEMON) {
    if(code == NS_STATE_COM_REQUEST || code == NS_STATE_COM_RESPONSE)
      return 0;
    
  } else {
    ns_log_warning("undefined application role, discarding message! (%d)", role);
  }
  ns_log_info("received message with invalid code (%d : %s).", code, ns_state_to_str(code));
  return -1;
}

void ns_set_credentials(ns_context_t *context, char *identity, char *key) {
  
#ifdef NS_DEBUG
  if(identity == NULL)
    ns_log_error("identity is NULL");
    
  if(key == NULL)
    ns_log_error("key is NULL");
#endif

  memcpy(context->identity, identity, NS_IDENTITY_LEN);
  memcpy(context->key, key, NS_RIN_KEY_LEN);
}

void ns_set_role(ns_context_t *context, ns_role_t role) {
  
  context->role = role;
}

static inline ns_context_t*
ns_alloc_context() {
#ifdef CONTIKI
  return (ns_context_t*) memb_alloc(&ns_context_store);
#else
  return (ns_context_t*) malloc(sizeof(ns_context_t));
#endif /* CONTIKI */
}

static inline void
ns_free_context(ns_context_t *ctx) {
#ifdef CONTIKI
  memb_free(&ns_context_store, ctx);
#else
  free(ctx);
#endif /* CONTIKI */
}

ns_context_t* ns_initialize_context(void *app, ns_handler_t *handler) {
  
#ifdef CONTIKI
  /* Initialize memory blocks */
  memb_init(&ns_context_store);
  memb_init(&ns_peers_store);
  memb_init(&ns_out_buf_store);
#endif
  
  ns_context_t *context = NULL;
  context = ns_alloc_context();
  
  if(context) {
    memset(context, 0, sizeof(ns_context_t));
    context->app = app;
    context->handler = handler;
    
#ifdef CONTIKI
    LIST_STRUCT_INIT(context, peers);
#endif /* CONTIKI */
  }
  
  return context;
}

void ns_destroy_context(ns_context_t *context) {
  ns_free_peers(context);
  ns_free_context(context);
}

void ns_free_peers(ns_context_t *context) {
  ns_peer_t *peer;

#ifdef CONTIKI
  for(peer = list_head(context->peers); peer; peer = list_item_next(peer)) {
    list_remove(context->peers, peer);
    ns_free_peer(peer);
  }
#else /* CONTIKI */
  ns_peer_t *tmp;
  HASH_ITER(hh, context->peers, peer, tmp) {
    HASH_DEL(context->peers, peer);
    ns_free_peer(peer);
  }
#endif /* CONTIKI */

}

uint64_t htonll(uint64_t val) {
  
  int16_t i = 1;
  /* host is little endian, convert from host to network-byte-order */
  if(i & 0x10) {
#ifndef CONTIKI
    return (((uint64_t)htonl(val)) << 32) + htonl(val >> 32);
#else
    return (((uint64_t)UIP_HTONL(val)) << 32) + UIP_HTONL(val >> 32);
#endif /* CONTIKI */
  } else {
    return val;
  }
}

uint64_t ntohll(uint64_t val) {
  
  /* htonll flips the bytes if the host is little endian, so they can be used
     for both cases */
  return htonll(val);
}