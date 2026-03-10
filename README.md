# xtls

xtls is a convenient C++ abstraction library for TLS, which does not do any crypto on its own but is built in an extensible way to allow implementation using various TLS libraries. Currently, OpenSSL is the only built-in backend.

Apart from that, this library has some optional things, such as a full blown `TlsSocket` class that lets you create a blocking TLS client with a few lines of C++, as well as an async version of `TlsSocket` that utilizes the [Arc](https://github.com/dankmeme01/arc) async framework.
