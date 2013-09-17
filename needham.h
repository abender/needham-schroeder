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

#ifndef _NEEDHAM_SCHROEDER_H_
#define _NEEDHAM_SCHROEDER_H_

#include <sys/types.h>

#ifndef CONTIKI

#include <sys/time.h>
#include <netinet/in.h>

#endif /* CONTIKI */

//#include <time.h>
#include <inttypes.h>

#include "ns_util.h"


#ifndef CONTIKI

typedef unsigned int clock_time_t;

#include "uthash.h"

#endif /* CONTIKI */

#ifdef CONTIKI

#include "uip.h"
#include "list.h"

#endif /* CONTIKI */

/* LOGGING: Set NS_LOG_LEVEL in "util.h" to the desired level, which can be:
 *
 * 0: debug
 * 1: info
 * 2: warning
 * 3: error
 * 4: fatal
 */

/* CAUTION: The library currently only supports multiples of 16 for NS_KEY_LENGTH,
 * NS_IDENTITY_LENGTH and NS_NONCE_LENGTH.
 * 
 * NS_RIN_KEY_LENGTH MUST be 16 for the currently used rijndael implementation.
 *
 * All values in Bytes
 */
#define NS_BLOCKSIZE 16       // Blocksize of the encryption algorithm used for NS
#define NS_KEY_LENGTH 16      // Length of the tmp-key used for DTLS
#define NS_RIN_KEY_LENGTH 16  // Length of the AES Key
#define NS_IDENTITY_LENGTH 16 // Length of global identifiers for communication partners
#define NS_NONCE_LENGTH 16    // Nonce length used in Needham-Schroeder

/* Length of the timestamp used to validate messages, must be 8 because
   ns_create_timestamp creates an 8 bytes long timestamp. */
#define NS_TIMESTAMP_LENGTH 8

/* Calculate the length that is needed for a block of \p len Bytes to match
   multiples of NS_BLOCKSIZE */
#define ns_padded_length(len) \
  (((len) % NS_BLOCKSIZE == 0) ? (len) : ((len) - ((len) % NS_BLOCKSIZE) + NS_BLOCKSIZE))

/* Message sizes */
   
#define NS_ENC_COM_REQ_LENGTH \
  (ns_padded_length(NS_KEY_LENGTH+NS_IDENTITY_LENGTH+NS_TIMESTAMP_LENGTH))

#define NS_ENC_KEY_RESPONSE_LENGTH \
  (ns_padded_length(NS_NONCE_LENGTH + NS_IDENTITY_LENGTH + NS_KEY_LENGTH + \
   NS_ENC_COM_REQ_LENGTH))

#define NS_ENC_COM_CHALLENGE_LENGTH \
  (ns_padded_length(NS_NONCE_LENGTH))

#define NS_ENC_COM_RESPONSE_LENGTH \
  (ns_padded_length(NS_NONCE_LENGTH))

#define NS_KEY_REQUEST_LENGTH 1+2*NS_IDENTITY_LENGTH+NS_NONCE_LENGTH

/* Buffer sizes for each application type. */
#define NS_DAEMON_BUFFER_SIZE (1 + NS_ENC_COM_REQ_LENGTH)
#define NS_SERVER_BUFFER_SIZE NS_KEY_REQUEST_LENGTH
#define NS_CLIENT_BUFFER_SIZE (1 + NS_ENC_KEY_RESPONSE_LENGTH)

/* Retransmissions */
#define NS_RETRANSMIT_TIMEOUT 5 // Timeout length for retransmissions in seconds
#define NS_RETRANSMIT_MAX 3     // Maximum retransmissions before NS_ERR_TIMEOUT is thrown.
                                //  A value of 3 means 4 attempts in total

/* Key lifetime, in seconds. This is used to antagonize replay-attacks and says
   when the Daemon will reject packets with communication requests. */
#define NS_KEY_LIFETIME (60 * 5)

/* Message codes */
typedef enum {
  NS_STATE_INITIAL = 0,
  NS_STATE_KEY_REQUEST,
  NS_STATE_KEY_RESPONSE,
  NS_STATE_COM_REQUEST,
  NS_STATE_COM_CHALLENGE,
  NS_STATE_COM_RESPONSE,
  NS_STATE_COM_CONFIRM,
  NS_STATE_FINISHED
} ns_state_t;

/* Message error codes */
typedef enum {
  NS_ERR_UNKNOWN_ID = 17,
  NS_ERR_REJECTED,
  NS_ERR_NONCE,
  NS_ERR_TIMEOUT,
  NS_ERR_UNKNOWN
} ns_error_t;

typedef enum {
  NS_ROLE_CLIENT = 0,
  NS_ROLE_SERVER,
  NS_ROLE_DAEMON
} ns_role_t;

#ifdef CONTIKI
typedef struct {
  unsigned char size;
  uip_ipaddr_t addr;
  unsigned short port;
} ns_abstract_address_t;

#else /* CONTIKI */
/* IPv4/IPv6 Address abstraction */
typedef struct {
  socklen_t size;
  union {
    struct sockaddr     sa;
    struct sockaddr_storage st;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
  } addr;
} ns_abstract_address_t;
#endif /* CONTIKI */


struct ns_context_t;

typedef struct {
  
  /**
   * Callback to read from the network (not used, can be NULL for all roles)
   */
  int (*read)(struct ns_context_t *context, ns_abstract_address_t *addr,
        uint8_t *data, size_t len);
  
  /**
   * Callback to write to the network. This must send a packet to the given
   * address.
   *
   * @param context
   * @param addr The address struct this pointer points at contains the address
   *        informations the packet must be send to.
   * @param data The data which needs to be sent
   * @param len Length of the data bufffer
   */
  int (*write)(struct ns_context_t *context, ns_abstract_address_t *addr,
        uint8_t *data, size_t len);
  
  /**
   * Callback to store a key. This must be implemented for the client and daemon,
   * which will store a key if the negotiation succeeded.
   *
   * @param identity_name Contains the name of the communication partner
   * @param key Contains the key which just has been negotiated
   */
  int (*store_key)(char *identity_name, char *key);
  
  /**
   * Callback to get the key for the given \p identity_name . Must be implemented
   * for the server.
   *
   * @param identity_name The name which is used to search for the corresponding key.
   * @param key If there is a key found for the given identity_name, its key must be
   *        stored in this location so the library can use it.
   * @return This function must return the following codes:
   *   -1 : If the identity is not found (or no key exists for it)
   *    0 : on success
   */
  int (*get_key)(char *identity_name, char *key);
  
  /**
   * Callback to handle events. Fired events so far:
   *
   * - If the client encounters an unkown error (and exits)
   * - If the client receives a message from the server, that it doesn't know the
   *     given ids (NS_ERR_UNKNOWN_ID)
   */
  int (*event)(int code);
  
} ns_handler_t;

typedef struct {
#ifndef CONTIKI
  UT_hash_handle hh;
  time_t expires;
#else /* CONTIKI */
  struct ns_peer_t *next;
  unsigned long expires;
#endif /* CONTIKI */
  ns_abstract_address_t addr;
  char nonce[NS_NONCE_LENGTH];
  char identity[NS_IDENTITY_LENGTH];
  char key[NS_KEY_LENGTH];
  int state;
  uint8_t *msg_buf; /* buffer for messages, used for retransmissions */
  size_t msg_buf_len; /* length of the retransmission buffer */
  int retransmits; /* number of performed retransmissions */
  
} ns_peer_t;

typedef struct ns_context_t {
  
  ns_handler_t *handler; /* User callback functions */
  
#ifndef CONTIKI
  ns_peer_t *peers;
#else /* CONTIKI */
  LIST_STRUCT(peers);
#endif /* CONTIKI */
  
  void *app; /* Socket fd for Unix Systems or uip_udp_conn for Contiki */
  char nonce[NS_NONCE_LENGTH]; // FIXME: nonce not necessary here? nonce is stored per peer
  char identity[NS_IDENTITY_LENGTH];
  char key[NS_KEY_LENGTH];
  ns_role_t role;
  int state;
  
} ns_context_t;

#ifndef CONTIKI
/**
 * Creates and binds a (unix) socket to the given \p port and address family.
 *
 * @param port The port number the port should be bound to.
 * @param family The address family this port belongs to. (AF_INET, AF_INET6,...)
 */
int ns_bind_socket(int port, unsigned char family);
#endif /* CONTIKI */

/**
 * Creates a new context, which stores many informations needed by the library.
 * Applications must free this with ns_free_context().
 *
 * @param app A pointer to the network interface, e.g. the socket in Unix, or
 *      uip_udp_conn for Contiki
 * @param handler A handler for various functions like read/write from/to the
 *      network, key storage, etc. (see struct ns_handler_t)
 */
ns_context_t* ns_initialize_context(void *app, ns_handler_t *handler);

/**
 * Frees the context and all malloced memory related to it (e.g. the peers).
 *
 * @param context
 */
void ns_free_context(ns_context_t *context);

/**
 * Handles a message and usually is placed within a loop which retrieves messages
 * from the network (e.g. recvfrom() ) and passes it to this method.
 *
 * @param context The library context
 * @param addr The address the message comes from
 * @param buf The actual message content
 * @param len The message content length
 */
void ns_handle_message(ns_context_t *context, ns_abstract_address_t *addr,
      char *buf, size_t len);
      
/**
 * Set credentials for the application, only needed for the client and daemon
 *
 * @param context
 * @param identity The identities name, its length must be smaller or equal to
 *        NS_IDENTITY_LENGTH.
 * @param key The identities key, must be smaller or equal to NS_RIN_KEY_LENGTH.
 */
void ns_set_credentials(ns_context_t *context, char *identity, char *key);

/**
 * Sets the role of this conext. Needed for all applications.
 *
 * @param context
 * @param role The role this application has (see ns_role_t)
 */
void ns_set_role(ns_context_t *context, ns_role_t role);

/**
 * This function is called once by the client to start the negotiation process.
 *
 * @param context
 * @param server_address The address of the server as string
 * @param server_port The servers port in host-byte-order
 * @param partner_address The address of the daemon as string
 * @param partner_port The daemons port in host-byte-order
 * @param partner_identity The identity of the daemon
 */
void ns_get_key(ns_context_t *context, char *server_address, int server_port,
      char *partner_address, int partner_port, char *partner_identity);

/**
 * Returns the corresponding name for the given message code. (see ns_state_t,
 * ns_error_t) 0 -> "NS_STATE_INITIAL" etc.
 *
 * @param state
 */
char* ns_state_to_str(int state);

/**
 * Retransmit messages if there are any needed to be retransmitted. Fires an event
 * if maximal retransmissions are reached.
 *
 * @param context
 */
void ns_retransmit(ns_context_t *context);

#endif // _NEEDHAM_SCHROEDER_H_