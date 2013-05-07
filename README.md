# SNS - a simple Needham-Schroeder C-library

SNS is a small and simple C-library to perform the (symmetric) Needham-Schroeder(NS)-protocol. It provides basic functions to:

* Run a NS-server, creating and distributing keys for securing some other protocol (for example DTLS in pre-shared-key mode)
* Run a NS-daemon, waiting for clients to initialize the communication
* Run a NS-client, retrieving keys from the server and connecting to NS-daemons.

The library provides callback functions so the user may decide how keys will be stored/retrieved and how events will be handled.

See [wikipedia/Needham-Schroeder_protocol](http://en.wikipedia.org/wiki/Needham%E2%80%93Schroeder_protocol) for a description of the symmetric key exchange protocol.

## Usage

* Checkout the Git-repository, go to the main directory and run `make` to build the library.
* Go to the examples directory and run in seperate terminal(tab)s: 1) The server and daemon 2) The client.
* The client will connect to the server and daemon and perform the key exchange.
* See the examples code and `needham.h` for further informations

## Known Flaws / TODOs

* Currently the library only supports one key exchange at the time (TODO Session multiplexing)
* The library needs to handle lossy networks (TODO implement retransmissions)
* Compatibility with Contiki-OS is planned for future work

## Authors and Contact

SNS was written by Andreas Bender <bender@tzi.de>

If you have any questions, remarks, suggestion, improvements,
etc. feel free to drop a line at the addresses given above.

## License

This software is published under [MIT License](http://opensource.org/licenses/mit-license.php)

Some parts of the code are based on code from [tinydtls](http://tinydtls.sourceforge.net/) by Olaf Bergmann, published under [MIT License](http://opensource.org/licenses/mit-license.php)

Used libraries:

* UTHash library by Troy D. Hanson, published under [BSD License](http://troydhanson.github.io/uthash/license.html)
* [csiphash](https://github.com/majek/csiphash) published under [MIT License](http://opensource.org/licenses/mit-license.php)

