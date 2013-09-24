# seNS - a simple extended Needham-Schroeder C-library

seNS is a small and simple C-library to perform an extended (symmetric) Needham-Schroeder(NS)-protocol. Extended means in this case, that the basic NS-Protocol has been extended to make use of timestamps, which are used to antagonize replay attacks (see a description of the attack in "[Security Engineering](http://www.cl.cam.ac.uk/~rja14/book.html)" Chapter 3.7.2 by Ross Anderson). It provides basic functions to:

* Run a NS-server, creating and distributing keys for securing some other protocol (for example DTLS in pre-shared-key mode)
* Run a NS-daemon, waiting for clients to initialize the communication
* Run a NS-client, retrieving keys from the server and connecting to NS-daemons.

The library provides callback functions so the user may decide how keys will be stored/retrieved and how events will be handled.

The library has been tested with Debian/Linux Systems and OS X. Basic compatibility with [Contiki-OS](http://www.contiki-os.org/) is there, but needs improvements.

## Usage

* Checkout the Git-repository, go to the main directory and run `make` to build the library.
* Go to the examples directory and run in seperate terminal(tab)s: 1) The server and daemon 2) The client.
* The client will connect to the server and daemon and perform the key exchange.
* See the examples code and `needham.h` for further informations and configuration.

## Configuration

It is intended, that the user may choose lengths for all attributes of the NS-protocol (e.g. The length of identities, nonces and keys). While those for identities and nonces can be freely chosen, the lengths of the keys must be 16 Bytes for use with the Rijndael-implementation. If you want to use other key lengths make sure to overwrite `ns_encrypt_pkcs7`, `ns_encrypt` and `ns_decrypt` and set the values for `NS_BLOCKSIZE`, `NS_KEY_LENGTH` and `NS_RIN_KEY_LENGTH`.

The NS-client performs retransmissions to deal with lossy networks. To adjust its parameters change `NS_RETRANSMIT_TIMEOUT` and `NS_RETRANSMIT_MAX` accordingly.

See `needham.h` for a description of all modifiable values.

## TODOs

* **The timestamp validation is currently disabled for Contiki Applications until I've found a proper way to handle timestamps on constrained devices**
* Implement tests!
* Improve Contiki compatibility
* Implement other encryption methods
* Transmission error detection
* Check cleanups
* Vary the timeout of retransmissions

## Authors and Contact

seNS was written by Andreas Bender <bender@tzi.de>

If you have any questions, remarks, suggestion, improvements,
etc. feel free to drop a line at the address given above.

## License

This software is published under [MIT License](http://opensource.org/licenses/mit-license.php)

Some parts of the code are based on code from [tinydtls](http://tinydtls.sourceforge.net/) by Olaf Bergmann, published under [MIT License](http://opensource.org/licenses/mit-license.php)

Used libraries:

* UTHash library by Troy D. Hanson, published under [BSD License](http://troydhanson.github.io/uthash/license.html)
* [SHA256 by Aaron D. Gifford](http://www.aarongifford.com/computers/sha.html) published under BSD License

