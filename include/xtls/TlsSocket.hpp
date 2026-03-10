#pragma once
#ifdef XTLS_ENABLE_SOCKET

#include <xtls/Session.hpp>
#include <xtls/Context.hpp>
#include <qsox/TcpStream.hpp>

namespace xtls {

template <typename T>
inline TlsResult<T> mapResult(qsox::NetResult<T>&& res) {
    if (res.isOk()) {
        if constexpr (std::is_void_v<T>) {
            return geode::Ok();
        } else {
            return geode::Ok(std::move(res).unwrap());
        }
    }
    return geode::Err(TlsError::custom(res.unwrapErr().message()));
}

class TlsSocket {
public:
    TlsSocket(qsox::TcpStream stream, std::shared_ptr<Session> session);
    ~TlsSocket();

    TlsSocket(TlsSocket&&) = default;
    TlsSocket& operator=(TlsSocket&&) = default;

    static TlsResult<TlsSocket> connect(qsox::SocketAddress address, std::shared_ptr<Context> context, const std::string& hostname);
    static TlsResult<TlsSocket> connect(qsox::SocketAddress address, std::shared_ptr<Session> session);

    /// Sends data over this socket, returning the number of bytes sent.
    TlsResult<size_t> send(const void* buf, size_t size);
    /// Receives data from this socket, returning the number of bytes received.
    TlsResult<size_t> receive(void* buf, size_t size);

    qsox::NetResult<qsox::SocketAddress> localAddress() const;
    qsox::NetResult<qsox::SocketAddress> remoteAddress() const;

    /// Get the handle to the inner `qsox::TcpStream`.
    inline qsox::TcpStream& inner() noexcept {
        return m_stream;
    }

protected:
    qsox::TcpStream m_stream;
    std::shared_ptr<Session> m_session;

    template <typename T = void>
    TlsResult<T> performAction(auto&& fn) requires (std::is_invocable_r_v<TlsResult<T>, decltype(fn)>) {
        while (true) {
            auto res = fn();

            // always try to poll writes
            GEODE_UNWRAP_INTO(auto pair, m_session->getEncryptedData());
            auto [edata, esize] = pair;
            while (esize > 0) {
                GEODE_UNWRAP(mapResult(m_stream.sendAll(edata, esize)));
                GEODE_UNWRAP(m_session->notifyEncryptedSent(static_cast<size_t>(esize)));
            }

            if (res.isOk()) {
                if constexpr (std::is_void_v<T>) {
                    return geode::Ok();
                } else {
                    return geode::Ok(std::move(res).unwrap());
                }
            }

            auto err = std::move(res).unwrapErr();
            if (err == TlsError::WANT_READ) {
                uint8_t buf[4096];
                GEODE_UNWRAP_INTO(auto recvd, mapResult(m_stream.receive(buf, sizeof(buf))));
                GEODE_UNWRAP(m_session->feedEncryptedData(buf, static_cast<size_t>(recvd)));
            } else if (err == TlsError::WANT_WRITE) {
                // nothing to do here
                continue;
            } else {
                return geode::Err(std::move(err));
            }
        }
    }
};

}

#endif // XTLS_ENABLE_SOCKET
