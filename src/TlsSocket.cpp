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

template <typename T>
TlsResult<T> mapResult(qsox::NetResult<T>&& res) {
    if (res.isOk()) {
        return Ok(std::move(res).unwrap());
    }
    return Err(TlsError::custom(res.unwrapErr().message()));
}

TlsResult<TlsSocket> TlsSocket::connect(qsox::SocketAddress address, std::shared_ptr<Session> session) {
    GEODE_UNWRAP_INTO(auto stream, mapResult(qsox::TcpStream::connect(address)));
    (void) stream.setNoDelay(true);

    TlsSocket socket(std::move(stream), std::move(session));

    while (true) {
        auto res = socket.m_session->doHandshake();
        if (res.isOk()) break;

        // try to send any outgoing data
        GEODE_UNWRAP_INTO(auto pair, socket.m_session->getEncryptedData());
        auto [edata, esize] = pair;
        if (esize > 0) {
            GEODE_UNWRAP(mapResult(socket.m_stream.send(edata, esize)));
            GEODE_UNWRAP(socket.m_session->notifyEncryptedSent(static_cast<size_t>(esize)));
        }

        auto err = std::move(res).unwrapErr();
        if (err == TlsError::WANT_READ) {
            uint8_t buf[4096];
            GEODE_UNWRAP_INTO(auto recvd, mapResult(socket.m_stream.receive(buf, sizeof(buf))));
            GEODE_UNWRAP(socket.m_session->feedEncryptedData(buf, static_cast<size_t>(recvd)));
        } else if (err == TlsError::WANT_WRITE) {
            // nothing to do here
            continue;
        } else {
            return Err(std::move(err));
        }
    }

    return Ok(std::move(socket));
}

}

#endif // XTLS_ENABLE_SOCKET