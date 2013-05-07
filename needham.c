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

#include "needham.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "rin_wrapper.h"

/* Slightly modified version of resolve_address from libtinydtls by Olaf Bergmann
 ( MIT License: http://tinydtls.sourceforge.net/)  */
int
resolve_address(char *address, int port, ns_abstract_address_t *resolved) {
  
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
    log_fatal("getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
    case AF_INET6:
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

/**
 * Creates and binds an IPv6 UDP socket and returns its fd.
 */
int ns_bind_socket(int port, unsigned char family) {
  
  int s;
  s = socket(family, SOCK_DGRAM, 0);
  
  if(s < 0) {
    log_fatal("Could not create socket: %s", strerror(errno));
    exit(-1);
  }
  
  if(family == AF_INET6) {
    
    struct sockaddr_in6 listen_addr;

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin6_family = AF_INET6;
    listen_addr.sin6_port = htons(port);
    listen_addr.sin6_addr = in6addr_any;
    /* FIXME cleanup */
    if(bind(s, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
      log_fatal("Could not bind socket: %s", strerror(errno));
      exit(-1);
    }
    
  } else if(family == AF_INET) {
    
    struct sockaddr_in listen_addr;
    
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(port);
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    /* FIXME cleanup */
    if(bind(s, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) < 0) {
      log_fatal("Could not bind socket: %s", strerror(errno));
      exit(-1);
    }
    
  } else {
    log_fatal("unkown address family: %s", family);
    exit(-1);
  }
  return s;
}

/* --------------------------------- Common -------------------------------- */

/**
 * TODO implement!
 */
void alter_nonce(char *original, char *altered) {
  memcpy(altered, original, NS_NONCE_LENGTH);
}

/**
 * TODO implement!
 */
int ns_verify_nonce(char *nonce) {
  return 0;
}

/* ------------------------------- NS Server ------------------------------- */

/*
 * Handle a key request coming from \p socket . The packet is stored in \p in_buffer
 * and the sender in \p peer .
 */
void ns_handle_key_request(ns_server_handler_t *handler, int socket, char *in_buffer,
      ns_abstract_address_t *peer) {
  
  int get_sender, get_receiver;
  
  char id_sender[NS_IDENTITY_LENGTH+1];
  char id_receiver[NS_IDENTITY_LENGTH+1];
  char key_sender[NS_RIN_KEY_LENGTH+1] = { 0 };
  char key_receiver[NS_RIN_KEY_LENGTH+1] = { 0 };
  char nonce[NS_NONCE_LENGTH+1];
  
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
  
  log_info("Received STATE_KEY_REQUEST (Sender-ID: %s, Receiver-ID: %s).",
      id_sender, id_receiver);
  
  get_sender = handler->get_key(id_sender, key_sender);
  get_receiver = handler->get_key(id_receiver, key_receiver);
  
  /* Identity not found, send ERR_UNKNOWN_ID */
  if(get_sender == -1 || get_receiver == -1) {
    char out_buffer[1];
    out_buffer[0] = NS_ERR_UNKNOWN_ID;    
    log_info("Sent error NS_ERR_UNKNOWN_ID.");
    sendto(socket, out_buffer, sizeof(out_buffer), MSG_DONTWAIT, &peer->addr.sa, peer->size);
  
  /* Identities found, send..   {I_a, B, S_k, {S_k, A} K_b} K_a 
      1 Byte  : State (STATE_KEY_RESPONSE)
      encrypted K_s(
       16 Bytes : Nonce
       16 Bytes : Identity Receiver
       16 Bytes : tmp-Key
       32 Bytes : encrypted K_r(tmp-Key:16, Identity Sender16)
     ) */
  } else {
    /* State + Nonce + 2 Identities + 2 Keys (whole message) */
    char out_buffer[1 + NS_NONCE_LENGTH + 2*NS_IDENTITY_LENGTH + 2*NS_KEY_LENGTH];
    /* Key for sender-receiver communication */
    char tmp_key[NS_KEY_LENGTH+1] = { 0 };
    /* tmp_key, identity-sender */
    char r_packet[NS_KEY_LENGTH + NS_IDENTITY_LENGTH];
    /* Encrypted: tmp-key, identity-sender */
    char enc_r_packet[NS_KEY_LENGTH + NS_IDENTITY_LENGTH];
    /* Packet for the sender (excluding the state) */
    char s_packet[NS_NONCE_LENGTH + 2*NS_IDENTITY_LENGTH + 2*NS_KEY_LENGTH];
    
    random_key(tmp_key, NS_KEY_LENGTH);
    
    memcpy(r_packet, tmp_key, NS_KEY_LENGTH);
    memcpy(&r_packet[NS_KEY_LENGTH], id_sender, NS_IDENTITY_LENGTH);
    
    /* Encrypt package for receiver, tmp-key + sender-id */
    encrypt((u_char*) key_receiver, (u_char*) r_packet, (u_char*) enc_r_packet,
        sizeof(r_packet), NS_RIN_KEY_LENGTH);
    
    int pos = 0;
    memcpy(s_packet, nonce, NS_NONCE_LENGTH);
    pos += NS_NONCE_LENGTH;
    memcpy(&s_packet[pos], id_receiver, NS_IDENTITY_LENGTH);
    pos += NS_IDENTITY_LENGTH;
    memcpy(&s_packet[pos], tmp_key, NS_KEY_LENGTH);
    pos += NS_KEY_LENGTH;
    memcpy(&s_packet[pos], enc_r_packet, NS_KEY_LENGTH + NS_IDENTITY_LENGTH);
    
    out_buffer[0] = NS_STATE_KEY_RESPONSE;
    
    /* Encrypt package for sender */
    encrypt((u_char*) key_sender, (u_char*) s_packet, (u_char*) &out_buffer[1],
        sizeof(s_packet), NS_RIN_KEY_LENGTH);
    
    sendto(socket, out_buffer, sizeof(out_buffer), MSG_DONTWAIT, &peer->addr.sa, peer->size);
    log_info("Sent STATE_KEY_RESPONSE. (Sender-ID: %s, Receiver-ID: %s, tmp-Key: %s )",
        id_sender, id_receiver, tmp_key);
    
  }
}

void ns_server(ns_server_handler_t *handler, int port) {
  
  int s;
  char in_buffer[1 + 2*NS_IDENTITY_LENGTH + NS_NONCE_LENGTH];
  ns_abstract_address_t peer;
  
  s = ns_bind_socket(port, AF_INET6);
  
  peer.size = sizeof(peer.addr);

  log_info("Server running, waiting for key requests.");

  while(1) {
    recvfrom(s, in_buffer, sizeof(in_buffer), 0, &peer.addr.sa, &peer.size);
    
    if(in_buffer[0] == NS_STATE_KEY_REQUEST) {
      ns_handle_key_request(handler, s, in_buffer, &peer);      
    }
  }
}

/* ------------------------------- NS Client ------------------------------- */

void ns_send_key_request(ns_client_context_t *context) {

  char nonce[NS_NONCE_LENGTH];
  random_key(nonce, NS_NONCE_LENGTH);
  
  /* Message Code + Client identity + Partner identity + Nonce */
  char out_buffer[1+2*NS_IDENTITY_LENGTH+NS_NONCE_LENGTH] = { 0 };
  
  out_buffer[0] = NS_STATE_KEY_REQUEST;
  
  int pos = 1;
  memcpy(&out_buffer[pos], context->identity, strnlen(context->identity, NS_IDENTITY_LENGTH));
  pos += NS_IDENTITY_LENGTH;
  memcpy(&out_buffer[pos], context->peer->identity,
        strnlen(context->peer->identity, NS_IDENTITY_LENGTH));
  pos += NS_IDENTITY_LENGTH;
  memcpy(&out_buffer[pos], nonce, NS_NONCE_LENGTH);
  
  sendto(context->socket, out_buffer, sizeof(out_buffer), MSG_DONTWAIT,
        &context->server_addr.addr.sa, context->server_addr.size);
  context->peer->state = NS_STATE_KEY_REQUEST;
}

void ns_send_com_request(ns_client_context_t *context, char *packet) {
  
  char out_buffer[1+NS_KEY_LENGTH+NS_IDENTITY_LENGTH];
  
  out_buffer[0] = NS_STATE_COM_REQUEST;
  memcpy(&out_buffer[1], packet, NS_KEY_LENGTH+NS_IDENTITY_LENGTH);
  
  sendto(context->socket, out_buffer, sizeof(out_buffer), MSG_DONTWAIT,
        &context->peer->addr.addr.sa, context->peer->addr.size);
  context->peer->state = NS_STATE_COM_REQUEST;
  log_debug("sent com request to peer.");
}

void ns_handle_key_response(ns_client_context_t *context, char *packet) {

  char nonce[NS_NONCE_LENGTH] = { 0 };
  char partner_identity[NS_IDENTITY_LENGTH] = { 0 };
  char com_key[NS_KEY_LENGTH] = { 0 };
  char partner_packet[NS_KEY_LENGTH+NS_IDENTITY_LENGTH] = { 0 };
  
  char dec_packet[NS_NONCE_LENGTH+2*NS_IDENTITY_LENGTH+2*NS_KEY_LENGTH];
  
  decrypt((u_char*) context->key, (u_char*) &packet[1],
        (u_char*) dec_packet, sizeof(dec_packet), NS_RIN_KEY_LENGTH);
  
  /* Get values from the decrypted packet */
  int pos = 0;
  memcpy(nonce, &dec_packet[pos], NS_NONCE_LENGTH);
  pos += NS_NONCE_LENGTH;
  memcpy(partner_identity, &dec_packet[pos], NS_IDENTITY_LENGTH);
  pos += NS_IDENTITY_LENGTH;
  memcpy(com_key, &dec_packet[pos], NS_KEY_LENGTH);
  pos += NS_KEY_LENGTH;
  memcpy(partner_packet, &dec_packet[pos], NS_KEY_LENGTH+NS_IDENTITY_LENGTH);
  
  if(ns_verify_nonce(nonce) == 0) {
    context->handler->store_key(partner_identity, com_key);
    context->peer->state = NS_STATE_KEY_RESPONSE;
    log_debug("received new key from server.");
    ns_send_com_request(context, partner_packet);
  } else {
    log_fatal("nonce verification failed!");
  }
  
}

void ns_send_com_response(ns_client_context_t *context, char *altered_nonce) {
  
  char out_buffer[1+NS_NONCE_LENGTH] = { 0 };
  out_buffer[0] = NS_STATE_COM_RESPONSE;
  char key[NS_KEY_LENGTH] = { 0 };
  
  context->handler->get_key(context->peer->identity, key);
  
  encrypt((u_char*) key, (u_char*) altered_nonce, (u_char*) &out_buffer[1],
      NS_NONCE_LENGTH, NS_KEY_LENGTH);
      
  sendto(context->socket, out_buffer, sizeof(out_buffer), MSG_DONTWAIT,
        &context->peer->addr.addr.sa, context->peer->addr.size);
        
  log_info("sent com response, process completed.");
  context->peer->state = NS_STATE_FINISHED;
}

void ns_handle_com_challenge(ns_client_context_t *context, char *in_buffer) {
  
  char altered_nonce[NS_NONCE_LENGTH] = { 0 };
  alter_nonce(&in_buffer[1], altered_nonce);
  
  ns_send_com_response(context, altered_nonce);
}

int ns_get_key(ns_client_handler_t handler,
      char *server_address, char *partner_address, 
      int server_port, int client_port, int partner_port,
      char *client_identity, char *partner_identity, char *key) {


  ns_client_context_t context;
  ns_client_peer_t peer;
  
  ns_abstract_address_t server_addr, peer_addr, tmp_addr;

  /* Store client context informations */
  context.handler = &handler;
  context.server_addr = server_addr;
  context.peer = &peer;
  
  memcpy(context.key, key, NS_RIN_KEY_LENGTH);
  memcpy(context.identity, client_identity, NS_IDENTITY_LENGTH);
  
  /* Store peer informations */
  context.peer->addr = peer_addr;
  memcpy(context.peer->identity, partner_identity, NS_IDENTITY_LENGTH);
  context.peer->state = NS_STATE_INITIAL;
  
  /* Must be big enough for all request sizes (longest message is KEY_RESPONSE) */
  char in_buffer[1+NS_NONCE_LENGTH+2*NS_IDENTITY_LENGTH+2*NS_KEY_LENGTH] = { 0 };
  
  resolve_address(server_address, server_port, &context.server_addr);
  resolve_address(partner_address, partner_port, &context.peer->addr);
  
  context.socket = ns_bind_socket(client_port, context.server_addr.addr.sa.sa_family);
  
  ns_send_key_request(&context);
  log_debug("sent key request to %s", server_address);

  tmp_addr.size = sizeof(tmp_addr.addr);

  /* Exit loop when the process is finished or any error occured */
  while(context.peer->state != NS_STATE_FINISHED
        && context.peer->state < NS_ERR_UNKNOWN_ID) {
    // FIXME hier wird die Adresse vom peer verwendet, könnte aber auch vom server kommen
    recvfrom(context.socket, in_buffer, sizeof(in_buffer), 0, &tmp_addr.addr.sa, &tmp_addr.size);

    switch(in_buffer[0]) {
    case NS_STATE_KEY_RESPONSE:
//      memcpy(&context.server_addr->addr, &tmp.addr.sa, tmp.size);
//      context.server_addr->size = tmp.size;
      ns_handle_key_response(&context, in_buffer);
      break;
      
    case NS_STATE_COM_CHALLENGE:
      ns_handle_com_challenge(&context, in_buffer);
      break;
      
    case NS_ERR_UNKNOWN_ID:
      log_error("the server doesn't know the given id(s): %s, %s", client_identity,
            partner_identity);
      context.peer->state = NS_ERR_UNKNOWN_ID;
      break;

    default:
      log_error("received unknown message with code %d", in_buffer[0]);
      context.peer->state = NS_ERR_UNKNOWN;
      break;
    }
    
  }
  context.handler->result(context.peer->state);
  
  return 0;
}

/* ------------------------------- NS Daemon ------------------------------- */

void ns_handle_com_response(ns_daemon_context_t *context, char *in_buffer) {
  
  char nonce[NS_NONCE_LENGTH];
  
  decrypt((u_char*) context->peer_key, (u_char*) &in_buffer[1], (u_char*) nonce,
      sizeof(nonce), NS_KEY_LENGTH);
      
  if(ns_verify_nonce(nonce) == 0) {
    log_info("completed ns-handshake and stored new key.");
  /* The nonce verification failed, delete the previously stored key */
  } else {
    // TODO implement
  }
}

void ns_send_com_challenge(ns_daemon_context_t *context, ns_abstract_address_t *peer,
      char *client_identity) {
  
  char out_buffer[1 + NS_NONCE_LENGTH] = { 0 };
  char nonce[NS_NONCE_LENGTH] = { 0 };
  char key[NS_KEY_LENGTH] = { 0 };
  
  out_buffer[0] = NS_STATE_COM_CHALLENGE;
  
  /* FIXME add padding when NONCE_LENGTH % 16 != 0 and check corresponding decryption */
  random_key(nonce, NS_NONCE_LENGTH);
  
  /* Get key for this communication partner */
  context->handler->get_key(client_identity, key);
  
  encrypt((u_char*) key, (u_char*) nonce, (u_char*) &out_buffer[1],
      NS_NONCE_LENGTH, NS_KEY_LENGTH);
  
  sendto(context->socket, out_buffer, sizeof(out_buffer), MSG_DONTWAIT,
        &peer->addr.sa, peer->size);
  log_debug("Sent com challenge to peer.");
}

void ns_handle_com_request(ns_daemon_context_t *context, ns_abstract_address_t *peer,
      char *in_buffer) {
  
  char dec_pkt[NS_KEY_LENGTH+NS_IDENTITY_LENGTH];

  decrypt((u_char*) context->daemon_ns_key, (u_char*) &in_buffer[1], (u_char*) dec_pkt,
      sizeof(dec_pkt), NS_RIN_KEY_LENGTH);
      
  char key[NS_KEY_LENGTH+1] = { 0 };
  char client_identity[NS_IDENTITY_LENGTH+1] = { 0 };
    
  memcpy(key, dec_pkt, NS_KEY_LENGTH);
  memcpy(client_identity, &dec_pkt[NS_KEY_LENGTH], NS_IDENTITY_LENGTH);
  
  log_debug("received com request. ( Sender-ID: %s, Key: %s )", client_identity, key);
  
  context->handler->store_key(client_identity, key);
  
  // FIXME quick and dirty, this way only 1 client can talk to the daemon at the
  // same time
  memcpy(context->peer_key, key, NS_KEY_LENGTH);
  
  ns_send_com_challenge(context, peer, client_identity);
}

void ns_daemon(ns_daemon_handler_t *handler, int port, char *key) {
  
  ns_daemon_context_t context;
  context.handler = handler;
  memcpy(context.daemon_ns_key, key, NS_RIN_KEY_LENGTH);
  int s;
  char in_buffer[1+NS_KEY_LENGTH+NS_IDENTITY_LENGTH] = { 0 };
  ns_abstract_address_t peer;
  
  s = ns_bind_socket(port, AF_INET6);
  context.socket = s;
  
  peer.size = sizeof(peer.addr);

  log_info("daemon running, waiting for com requests.");

  while(1) {
    recvfrom(s, in_buffer, sizeof(in_buffer), 0, &peer.addr.sa, &peer.size);

    if(in_buffer[0] == NS_STATE_COM_REQUEST) {
      ns_handle_com_request(&context, &peer, in_buffer);
    } else if(in_buffer[0] == NS_STATE_COM_RESPONSE) {
      ns_handle_com_response(&context, in_buffer);
    } else {
      log_error("received unknown packet (code: %d)", in_buffer[0]);
    }
  }

}
