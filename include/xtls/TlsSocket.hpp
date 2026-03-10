#pragma once
#ifdef XTLS_ENABLE_SOCKET

#include <xtls/Session.hpp>
#include <xtls/Context.hpp>
#include <qsox/TcpStream.hpp>

namespace xtls {

class TlsSocket {
public:
    TlsSocket(qsox::TcpStream stream, std::shared_ptr<Session> session);
    ~TlsSocket();

    TlsSocket(TlsSocket&&) = default;
    TlsSocket& operator=(TlsSocket&&) = default;

    static TlsResult<TlsSocket> connect(qsox::SocketAddress address, std::shared_ptr<Context> context, const std::string& hostname);
    static TlsResult<TlsSocket> connect(qsox::SocketAddress address, std::shared_ptr<Session> session);

private:
    qsox::TcpStream m_stream;
    std::shared_ptr<Session> m_session;
};

}

#endif // XTLS_ENABLE_SOCKET
