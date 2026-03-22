#pragma once
#ifdef XTLS_ENABLE_ARC_SOCKET

#include "TlsSocket.hpp"
#include <arc/future/Future.hpp>
#include <arc/runtime/IoDriver.hpp>
#include <arc/net/EventIoBase.hpp>

namespace xtls {

class AsyncTlsSocket : public TlsSocket, public arc::EventIoBase<AsyncTlsSocket> {
public:
    AsyncTlsSocket(qsox::TcpStream stream, std::shared_ptr<Session> session, arc::Registration io);
    ~AsyncTlsSocket();

    AsyncTlsSocket(AsyncTlsSocket&&) = default;
    AsyncTlsSocket& operator=(AsyncTlsSocket&&) = default;

    static arc::Future<TlsResult<AsyncTlsSocket>> connect(qsox::SocketAddress address, std::shared_ptr<Context> context, const std::string& hostname);
    static arc::Future<TlsResult<AsyncTlsSocket>> connect(qsox::SocketAddress address, std::shared_ptr<Session> session);

    /// Sends data over this socket, returning the number of bytes sent.
    arc::Future<TlsResult<size_t>> send(const void* buf, size_t size);
    /// Receives data from this socket, returning the number of bytes received.
    arc::Future<TlsResult<size_t>> receive(void* buf, size_t size);

    /// Tries to send data over this socket without blocking, returning the number of bytes sent.
    /// If no data could be sent, returns an error. If the supplied size is 0, returns Ok(0).
    TlsResult<size_t> trySend(const void* buf, size_t size);

    arc::Future<TlsResult<>> flushAll();
    TlsResult<> tryFlushSync();

private:
    arc::Future<TlsResult<>> handshake();
    arc::Future<TlsResult<>> handleErr(const TlsError& err);
};

}

#endif // XTLS_ENABLE_ARC_SOCKET
