# The Illustrated TLS Connection

Published at https://tls13.ulfheim.net

- `site/`: page source for the finished product
- `server/main.c`: server code
- `client/main.c`: client code
- `boringssl/`: patch of boringssl that removes any random aspects of the documented connection
- `captures/`: PCAP and keylog files

See also https://github.com/syncsynchalt/illustrated-tls

### Build instructions

If you'd like a working example that reproduces exactly the same bytes documented on the site, the following should work:
```
git clone https://github.com/syncsynchalt/illustrated-tls13.git
cd illustrated-tls13/
cd boringssl/
make
cd ../server/
make
cd ../client/
make
cd ../server/

```
Then open two terminals and run `./server` in the server/ subdir and `./client` in the client/ subdir.

This has been shown to work on MacOS 10.14 and various Linuxes and only has a few easy-to-find dependencies: gcc or clang, golang, cmake, make, patch.
