# sNS - a simple Needham-Schroeder C-library

sNS is a small and simple C-library to perform the (symmetric) Needham-Schroeder(NS)-protocol. It provides basic functions to:

* Run a NS-server, creating and distributing keys for securing some other protocol (for example DTLS in pre-shared-key mode)
* Run a NS-daemon, waiting for clients to initialize the communication
* Run a NS-client, retrieving keys from the server and connecting to NS-daemons.

The library provides callback functions so the user may decide how keys will be stored/retrieved and how events will be handled.

See [wikipedia/Needham-Schroeder_protocol](http://en.wikipedia.org/wiki/Needham%E2%80%93Schroeder_protocol) for a description of the symmetric key exchange protocol.

The library has been tested with Debian/Linux Systems and OS X.

## Usage

* Checkout the Git-repository, go to the main directory and run `make` to build the library.
* Go to the examples directory and run in seperate terminal(tab)s: 1) The server and daemon 2) The client.
* The client will connect to the server and daemon and perform the key exchange.
* See the examples code and `needham.h` for further informations

It is intended, that the user may choose the lengths for identities, nonces and keys. With the current implementation there are the following limitations:

* All of these 4 values must be multiples of 16. This is due to the blocksize of the used rijndael implementation and missing padding
* The key length for the Needham-Schroeder process must be exactly 16 due to the used rijndael library. If you want to use other key lengths make sure to overwrite the `encrypt` and `decrypt` functions.

The length definitions can be found in `needham.h`:

    #define NS_KEY_LENGTH 16
    #define NS_RIN_KEY_LENGTH 16
    #define NS_IDENTITY_LENGTH 16
    #define NS_NONCE_LENGTH 16

Where `NS_RIN_KEY_LENGTH` is the key used for the Needham-Schroeder-process itself and `NS_KEY_LENGTH` the negotiated key used later on in some other protocol.

The NS-client performs retransmissions to deal with lossy networks. To adjust its parameters change `NS_RETRANSMIT_TIMEOUT` and `NS_RETRANSMIT_MAX` accordingly.

## TODOs

* Cleanup of peers for the client and server (daemon should be working, check it.)
* Implement tests!
* Compatibility with Contiki-OS is planned for future work
* Implement padding and other encryption methods
* Vary the timeout of retransmissions (It could be possible that 2 clients try to send over the same medium exactly the same time and the packets collide each time)

## Authors and Contact

sNS was written by Andreas Bender <bender@tzi.de>

If you have any questions, remarks, suggestion, improvements,
etc. feel free to drop a line at the address given above.

## License

This software is published under [MIT License](http://opensource.org/licenses/mit-license.php)

Some parts of the code are based on code from [tinydtls](http://tinydtls.sourceforge.net/) by Olaf Bergmann, published under [MIT License](http://opensource.org/licenses/mit-license.php)

Used libraries:

* UTHash library by Troy D. Hanson, published under [BSD License](http://troydhanson.github.io/uthash/license.html)
* [SHA256 by Aaron D. Gifford](http://www.aarongifford.com/computers/sha.html) published under BSD License

