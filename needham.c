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

#ifdef CONTIKI
/* Storage for peers */
MEMB(ns_peers_store, ns_peer_t, NS_MAX_PEERS);

/* Storage for context */
MEMB(ns_context_store, ns_context_t, 1);
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

#ifndef CONTIKI
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
  
#ifdef NSDEBUG
  if(NS_NONCE_LENGTH > SHA256_BLOCK_LENGTH) {
    ns_log_warning("the nonce length (%d) is bigger than the provided hash buffer (%d)",
          NS_NONCE_LENGTH, SHA256_BLOCK_LENGTH);
  }
  if(NS_NONCE_LENGTH > SHA256_DIGEST_LENGTH) {
    ns_log_warning("the nonce length (%d) is bigger than the sha256 digest (%d)",
          NS_NONCE_LENGTH, SHA256_DIGEST_LENGTH);
  }
#endif
  
  char buf[SHA256_DIGEST_LENGTH] = { 0 };

  memcpy(buf, original, NS_NONCE_LENGTH);
  
	SHA256_CTX	ctx256;
	SHA256_Init(&ctx256);
	SHA256_Update(&ctx256, (unsigned char*) buf, NS_NONCE_LENGTH);
  SHA256_Final((uint8_t*) buf, &ctx256);
	
  memcpy(altered, buf, NS_NONCE_LENGTH);
}

int ns_verify_nonce(char *original_nonce, char *verify_nonce) {
  
  char altered_nonce[NS_NONCE_LENGTH];
  ns_alter_nonce(original_nonce, altered_nonce);
  
  if(memcmp(altered_nonce, verify_nonce, NS_NONCE_LENGTH) == 0) {
    return 0;
  } else {
#ifdef NSDEBUG
    ns_log_debug("--------------------");
    ns_log_debug("nonce verification failed, my altered nonce is:");
    ns_dump_bytes_to_hex((unsigned char*) altered_nonce, NS_NONCE_LENGTH);
    ns_log_debug("but the received nonce is:");
    ns_dump_bytes_to_hex((unsigned char*) verify_nonce, NS_NONCE_LENGTH);
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
  
  memcpy(partner->identity, partner_identity, NS_IDENTITY_LENGTH);
  
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

  /* store this packet for possible retransmissions */
  peer->msg_buf = (uint8_t*) malloc(len);
  if(!peer->msg_buf) {
    ns_log_warning("no memory to buffer this message, if it is lost a retransmit timeout will occur.");
    peer->retransmits = NS_RETRANSMIT_MAX+1;
  } else {
    memcpy(peer->msg_buf, data, len);
    peer->msg_buf_len = len;
    peer->retransmits = 0;    
  }
  context->handler->write(context, &peer->addr, data, len);
}

void ns_send_key_request(ns_context_t *context, ns_peer_t *server, ns_peer_t *peer) {
  
  ns_random_key(server->nonce, NS_NONCE_LENGTH);
  
  /* Message Code + Client identity + Partner identity + Nonce */
  char out_buffer[1+2*NS_IDENTITY_LENGTH+NS_NONCE_LENGTH] = { 0 };
  
  out_buffer[0] = NS_STATE_KEY_REQUEST;
  
  int pos = 1;
  memcpy(&out_buffer[pos], context->identity, strnlen(context->identity, NS_IDENTITY_LENGTH));
  pos += NS_IDENTITY_LENGTH;
  memcpy(&out_buffer[pos], peer->identity,
        strnlen(peer->identity, NS_IDENTITY_LENGTH));
  pos += NS_IDENTITY_LENGTH;
  memcpy(&out_buffer[pos], server->nonce, NS_NONCE_LENGTH);
  
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
  
  char id_sender[NS_IDENTITY_LENGTH+1] = { 0 };
  char id_receiver[NS_IDENTITY_LENGTH+1] = { 0 };
  char key_sender[NS_RIN_KEY_LENGTH+1] = { 0 };
  char key_receiver[NS_RIN_KEY_LENGTH+1] = { 0 };
  char nonce[NS_NONCE_LENGTH+1] = { 0 };
  
  memset(id_sender, 0, sizeof(id_sender));
  memset(id_receiver, 0, sizeof(id_receiver));
  memset(nonce, 0, sizeof(nonce));
  
  /* Get values from incoming packet (sender, receiver, nonce) */
  int pos = 1;
  memcpy(&id_sender, &in_buffer[1], NS_IDENTITY_LENGTH);
  pos += NS_IDENTITY_LENGTH;
  memcpy(&id_receiver, &in_buffer[pos], NS_IDENTITY_LENGTH);
  pos += NS_IDENTITY_LENGTH;
  memcpy(&nonce, &in_buffer[pos], NS_NONCE_LENGTH);
  
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
  
  /* Identities found, send  {I_a, B, S_k, {S_k, A, T} K_b} K_a */
  } else {
    char out_buffer[1 + NS_ENC_KEY_RESPONSE_LENGTH];
    /* Key for sender-receiver communication */
    char tmp_key[NS_KEY_LENGTH+1] = { 0 };
    /* The packet for the daemon, without message code
       (tmp_key, identity-sender, timestamp) */
    char r_packet[NS_KEY_LENGTH + NS_IDENTITY_LENGTH + NS_TIMESTAMP_LENGTH] = { 0 };
    char enc_r_packet[NS_ENC_COM_REQ_LENGTH];
    /* Packet for the sender (excluding the state), unencrypted */
    char s_packet[NS_NONCE_LENGTH + NS_IDENTITY_LENGTH + NS_KEY_LENGTH +
                  NS_ENC_COM_REQ_LENGTH];
    
    ns_random_key(tmp_key, NS_KEY_LENGTH);
    
    /* Build packet for the daemon */

    /* create the timestamp in network-byte-order */
    char timestamp[NS_TIMESTAMP_LENGTH];
    ns_create_timestamp(timestamp);

    memcpy(r_packet, tmp_key, NS_KEY_LENGTH);
    memcpy(&r_packet[NS_KEY_LENGTH], id_sender, NS_IDENTITY_LENGTH);
    memcpy(&r_packet[NS_KEY_LENGTH + NS_IDENTITY_LENGTH], timestamp, sizeof(timestamp));

#ifdef NSDEBUG
    char pkey[NS_RIN_KEY_LENGTH+1] = {0};
    memcpy(pkey, key_receiver, NS_RIN_KEY_LENGTH);
    ns_log_debug("Key used to encrypt ticket: %s", pkey);
    ns_dump_bytes_to_hex((unsigned char*)key_receiver, NS_RIN_KEY_LENGTH);
#endif

    /* Encrypt package for receiver, tmp-key + sender-id + timestamp */
    ns_encrypt_pkcs7((u_char*) key_receiver, (u_char*) r_packet, (u_char*) enc_r_packet,
        sizeof(r_packet), NS_RIN_KEY_LENGTH);
        
    char altered_nonce[NS_NONCE_LENGTH] = { 0 };
    ns_alter_nonce(nonce, altered_nonce);
    
    /* Build packet for client */
    int pos = 0;
    memcpy(s_packet, altered_nonce, NS_NONCE_LENGTH);
    pos += NS_NONCE_LENGTH;
    memcpy(&s_packet[pos], id_receiver, NS_IDENTITY_LENGTH);
    pos += NS_IDENTITY_LENGTH;
    memcpy(&s_packet[pos], tmp_key, NS_KEY_LENGTH);
    pos += NS_KEY_LENGTH;
    memcpy(&s_packet[pos], enc_r_packet, sizeof(enc_r_packet));
    
    out_buffer[0] = NS_STATE_KEY_RESPONSE;

    /* Encrypt package for sender */
    ns_encrypt_pkcs7((u_char*) key_sender, (u_char*) s_packet, (u_char*) &out_buffer[1],
        sizeof(s_packet), NS_RIN_KEY_LENGTH);
    
    context->handler->write(context, &peer->addr, (uint8_t*) out_buffer, sizeof(out_buffer));
    
    ns_log_info("Sent STATE_KEY_RESPONSE. (Sender-ID: %s, Receiver-ID: %s, tmp-Key: %s)",
      id_sender, id_receiver, tmp_key);
    
  }
}

void ns_handle_key_response(ns_context_t *context, ns_peer_t *server,
       char *packet, size_t len) {
  
  ns_reset_buffer(server);
  
  char altered_nonce[NS_NONCE_LENGTH] = { 0 };
  char partner_identity[NS_IDENTITY_LENGTH] = { 0 };
  char com_key[NS_KEY_LENGTH] = { 0 };
  char partner_packet[NS_ENC_COM_REQ_LENGTH] = { 0 };

  char dec_packet[NS_ENC_KEY_RESPONSE_LENGTH];

  ns_decrypt((u_char*) context->key, (u_char*) &packet[1],
          (u_char*) dec_packet, sizeof(dec_packet), NS_RIN_KEY_LENGTH);

  /* Get values from the decrypted packet */
  int pos = 0;
  memcpy(altered_nonce, &dec_packet[pos], sizeof(altered_nonce));
  pos += sizeof(altered_nonce);
  memcpy(partner_identity, &dec_packet[pos], sizeof(partner_identity));
  pos += sizeof(partner_identity);
  memcpy(com_key, &dec_packet[pos], sizeof(com_key));
  pos += sizeof(com_key);
  memcpy(partner_packet, &dec_packet[pos], sizeof(partner_packet));
  
  ns_peer_t *partner;
  partner = ns_find_peer_by_identity(context, partner_identity);
  
  if(!partner) {
    ns_log_warning("received key response with unknown partner identity, discarding packet.");
    return;
  }

  if(ns_verify_nonce(server->nonce, altered_nonce) == 0) {
    memcpy(partner->key, com_key, NS_KEY_LENGTH);
    context->state = NS_STATE_KEY_RESPONSE;
    ns_log_debug("received new key from server.");
    ns_send_com_request(context, partner, partner_packet);
  } else {
    ns_log_fatal("nonce verification failed!");
    context->state = NS_ERR_NONCE;
  }
}

void ns_send_com_request(ns_context_t *context, ns_peer_t *partner, char *packet) {
  
  char out_buffer[1+NS_ENC_COM_REQ_LENGTH];
  
  out_buffer[0] = NS_STATE_COM_REQUEST;
  memcpy(&out_buffer[1], packet, NS_ENC_COM_REQ_LENGTH);
  
  ns_send_buffered(context, partner, (uint8_t*) out_buffer, sizeof(out_buffer));
  
  context->state = NS_STATE_COM_REQUEST;
  ns_log_debug("sent com request to peer.");
}

void ns_handle_com_request(ns_context_t *context, ns_peer_t *peer,
      char *in_buffer, size_t len) {
  
  char dec_pkt[NS_ENC_COM_REQ_LENGTH];
  char packet_time[NS_TIMESTAMP_LENGTH];
  
#ifdef NSDEBUG
  char pkey[NS_RIN_KEY_LENGTH+1] = {0};
  memcpy(pkey, context->key, NS_RIN_KEY_LENGTH);
  ns_log_debug("Key used to decrypt: %s", pkey);
  ns_dump_bytes_to_hex((unsigned char*)context->key, NS_RIN_KEY_LENGTH);
#endif

  ns_decrypt((u_char*) context->key, (u_char*) &in_buffer[1], (u_char*) dec_pkt,
      sizeof(dec_pkt), NS_RIN_KEY_LENGTH);
    
  /* Temporarily remember the clients credentials, they will be stored via
     callback when the nonce verification succeeded */
  memcpy(peer->key, dec_pkt, NS_KEY_LENGTH);
  memcpy(peer->identity, &dec_pkt[NS_KEY_LENGTH], NS_IDENTITY_LENGTH);
  memcpy(packet_time, &dec_pkt[NS_KEY_LENGTH + NS_IDENTITY_LENGTH], NS_TIMESTAMP_LENGTH);
  
  /* Validate time. Do nothing if validation fails */
  if(ns_validate_timestamp(packet_time) != 0) {
    ns_log_warning("received packet with expired timestamp, discarding it."
      " (this may also be caused by a wrong key for decryption)");
    return;
  }
  
#ifdef NSDEBUG
  // FIXME shorter way to print these as strings?
  char d_key[NS_KEY_LENGTH+1] = { 0 };
  char d_identity[NS_IDENTITY_LENGTH+1] = { 0 };
  memcpy(d_key, peer->key, NS_KEY_LENGTH);
  memcpy(d_identity, peer->identity, NS_IDENTITY_LENGTH);
  ns_log_debug("received com request. ( Sender-ID: %s, Key: %s )", d_identity, d_key);
#endif
  
  ns_send_com_challenge(context, peer);
}

void ns_send_com_challenge(ns_context_t *context, ns_peer_t *peer) {
  
  char out_buffer[1 + NS_ENC_COM_CHALLENGE_LENGTH] = { 0 };

  out_buffer[0] = NS_STATE_COM_CHALLENGE;
  
  ns_random_key(peer->nonce, NS_NONCE_LENGTH);
  
  ns_encrypt_pkcs7((u_char*) peer->key, (u_char*) peer->nonce, (u_char*) &out_buffer[1],
      NS_NONCE_LENGTH, NS_KEY_LENGTH);
  
  context->handler->write(context, &peer->addr, (uint8_t*) out_buffer, sizeof(out_buffer));
  
  peer->state = NS_STATE_COM_CHALLENGE;
  ns_log_debug("Sent com challenge to peer.");
}

void ns_handle_com_challenge(ns_context_t *context, ns_peer_t *peer,
       char *in_buffer, size_t len) {
  
  ns_reset_buffer(peer);
  
  ns_log_debug("received com challenge");
  context->state = NS_STATE_COM_CHALLENGE;
  
  char dec_packet[NS_ENC_COM_CHALLENGE_LENGTH];
  
  ns_decrypt((u_char*) peer->key, (u_char*) &in_buffer[1],
        (u_char*) dec_packet, sizeof(dec_packet), NS_KEY_LENGTH);

  char altered_nonce[NS_NONCE_LENGTH] = { 0 };
  ns_alter_nonce(dec_packet, altered_nonce);

  ns_send_com_response(context, peer, altered_nonce);
}

void ns_send_com_response(ns_context_t *context, ns_peer_t *peer, char *nonce) {
  
  char out_buffer[1+NS_ENC_COM_RESPONSE_LENGTH] = { 0 };
  out_buffer[0] = NS_STATE_COM_RESPONSE;
  
  ns_encrypt_pkcs7((u_char*) peer->key, (u_char*) nonce, (u_char*) &out_buffer[1],
      NS_NONCE_LENGTH, NS_KEY_LENGTH);
      
  ns_send_buffered(context, peer, (uint8_t*) out_buffer, sizeof(out_buffer));
  
  context->state = NS_STATE_COM_RESPONSE;
  ns_log_debug("sent com response");
}

void ns_handle_com_response(ns_context_t *context, ns_peer_t *peer,
      char *in_buffer, size_t len) {

  char dec_packet[NS_ENC_COM_RESPONSE_LENGTH];
  
  ns_decrypt((u_char*) peer->key, (u_char*) &in_buffer[1], (u_char*) dec_packet,
      sizeof(dec_packet), NS_KEY_LENGTH);

  /* only store the key if the nonce verification succeded. otherwise the peer
     will be deleted without storing any credentials */
  if(ns_verify_nonce(peer->nonce, dec_packet) == 0) {
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
    if(p->msg_buf != NULL) {
      if(p->retransmits < NS_RETRANSMIT_MAX) {
        context->handler->write(context, &p->addr, p->msg_buf, p->msg_buf_len);
        p->retransmits++;
        ns_log_info("retransmitted message [%d/%d]", p->retransmits, NS_RETRANSMIT_MAX);
      /* max retransmittions reached */
      } else {
        ns_log_info("maximum retransmittions reached.");
        context->state = NS_ERR_TIMEOUT;
        context->handler->event(NS_ERR_TIMEOUT);
      }
    }
  }
}

void ns_reset_buffer(ns_peer_t *peer) {
  
  free(peer->msg_buf);
  peer->msg_buf = NULL;
  peer->msg_buf_len = 0;
  peer->retransmits = 0;
}

static inline ns_peer_t*
ns_alloc_peer() {
#ifdef CONTIKI
  return (ns_peer_t*) memb_alloc(&ns_peers_store);
#else
  return (ns_peer_t*) malloc(sizeof(ns_peer_t));
#endif /* CONTIKI */
}
#1
static inline void
ns_free_peer(ns_peer_t *peer) {
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
    ns_log_warning("no memory: alloc ns_peer_t");
    return peer;
  }
  
  /* ok, we have enough memory and a newly created peer, initialize it with data */
  memcpy(&peer->addr, peer_addr, sizeof(ns_abstract_address_t));
  ns_reset_peer(peer);
  
  ns_add_peer(context, peer);

  ns_log_debug("created new peer");
  
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
  
  memset(peer->nonce, 0, NS_NONCE_LENGTH);
  memset(peer->identity, 0, NS_IDENTITY_LENGTH);
  memset(peer->key, 0, NS_KEY_LENGTH);
  peer->expires = 0;
  peer->state = NS_STATE_INITIAL;
  peer->msg_buf = NULL;
  peer->msg_buf_len = 0;
  peer->retransmits = 0;
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

  uint64_t now; /* should be big enough for every reasonable timestamp */
  
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
#ifdef NSDEBUG
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
  
#ifdef NSDEBUG
  if(identity == NULL)
    ns_log_error("identity is NULL");
    
  if(key == NULL)
    ns_log_error("key is NULL");
#endif

  memcpy(context->identity, identity, NS_IDENTITY_LENGTH);
  memcpy(context->key, key, NS_RIN_KEY_LENGTH);
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
    if(peer->msg_buf)
      free(peer->msg_buf);
    ns_free_peer(peer);
  }
#else /* CONTIKI */
  ns_peer_t *tmp;
  HASH_ITER(hh, context->peers, peer, tmp) {
    HASH_DEL(context->peers, peer);
    if(peer->msg_buf)
      free(peer->msg_buf);
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