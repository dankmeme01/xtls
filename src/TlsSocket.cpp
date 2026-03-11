#include <xtls/TlsSocket.hpp>

#ifdef XTLS_ENABLE_SOCKET

using namespace geode;

namespace xtls {

TlsSocket::TlsSocket(qsox::TcpStream stream, std::shared_ptr<Session> session) :
    m_stream(std::move(stream)),
    m_session(std::move(session)) {}

TlsSocket::~TlsSocket() {}

TlsResult<TlsSocket> TlsSocket::connect(qsox::SocketAddress address, std::shared_ptr<Context> context, const std::string& hostname) {
    GEODE_UNWRAP_INTO(auto s, context->createSession());
    s->setHostname(hostname);
    return connect(address, std::move(s));
}

TlsResult<TlsSocket> TlsSocket::connect(qsox::SocketAddress address, std::shared_ptr<Session> session) {
    GEODE_UNWRAP_INTO(auto stream, mapResult(qsox::TcpStream::connect(address)));
    (void) stream.setNoDelay(true);

    TlsSocket socket(std::move(stream), std::move(session));
    GEODE_UNWRAP(socket.performAction([&] {
        return socket.m_session->doHandshake();
    }));

    return Ok(std::move(socket));
}

TlsResult<size_t> TlsSocket::send(const void* buf, size_t size) {
    return performAction<size_t>([&] {
        return m_session->write(buf, size);
    });
}

TlsResult<size_t> TlsSocket::receive(void* buf, size_t size) {
    return performAction<size_t>([&] {
        return m_session->read(buf, size);
    });
}

TlsResult<> TlsSocket::shutdown(qsox::ShutdownMode mode) {
    return mapResult(m_stream.shutdown(mode));
}

qsox::NetResult<qsox::SocketAddress> TlsSocket::localAddress() const {
    return m_stream.localAddress();
}

qsox::NetResult<qsox::SocketAddress> TlsSocket::remoteAddress() const {
    return m_stream.remoteAddress();
}

}

#endif // XTLS_ENABLE_SOCKET