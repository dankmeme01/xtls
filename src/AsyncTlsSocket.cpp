#include <xtls/AsyncTlsSocket.hpp>

#ifdef XTLS_ENABLE_ARC_SOCKET

using namespace arc;
using namespace geode;

namespace xtls {

AsyncTlsSocket::AsyncTlsSocket(qsox::TcpStream stream, std::shared_ptr<Session> session, Registration io) :
    TlsSocket(std::move(stream), std::move(session)), EventIoBase(std::move(io)) {}

AsyncTlsSocket::~AsyncTlsSocket() {}

Future<TlsResult<AsyncTlsSocket>> AsyncTlsSocket::connect(qsox::SocketAddress address, std::shared_ptr<Context> context, const std::string& hostname) {
    GEODE_CO_UNWRAP_INTO(auto s, context->createSession());
    s->setHostname(hostname);
    co_return co_await connect(address, std::move(s));
}

Future<TlsResult<AsyncTlsSocket>> AsyncTlsSocket::connect(qsox::SocketAddress address, std::shared_ptr<Session> session) {
    ARC_FRAME();

    GEODE_CO_UNWRAP_INTO(auto stream, mapResult(qsox::TcpStream::connectNonBlocking(address)));
    (void) stream.setNoDelay(true);

    auto rio = arc::Runtime::current()->ioDriver().registerIo(stream.handle(), arc::Interest::ReadWrite);
    AsyncTlsSocket socket(std::move(stream), std::move(session), std::move(rio));

    // wait until writable
    GEODE_CO_UNWRAP(mapResult(co_await socket.pollWritable()));
    auto err = socket.m_stream.getSocketError();
    if (err != qsox::Error::Success) {
        co_return Err(TlsError::custom(err.message()));
    }

    // perform the tls handshake
    GEODE_CO_UNWRAP(co_await socket.handshake());

    co_return Ok(std::move(socket));
}

arc::Future<TlsResult<>> AsyncTlsSocket::handshake() {
    while (true) {
        auto result = m_session->doHandshake();
        if (result.isOk()) {
            co_return Ok();
        }

        auto err = std::move(result).unwrapErr();
        GEODE_CO_UNWRAP(co_await this->handleErr(err));
    }
}

Future<TlsResult<size_t>> AsyncTlsSocket::send(const void* buf, size_t size) {
    while (true) {
        // write to the session
        auto result = m_session->write(buf, size);

        if (result.isErr()) {
            auto err = std::move(result).unwrapErr();
            GEODE_CO_UNWRAP(co_await this->handleErr(err));
            continue;
        }

        // try to flush all data
        GEODE_CO_UNWRAP(co_await this->flushAll());

        // return number of bytes successfully written
        co_return Ok(result.unwrap());
    }
}

TlsResult<size_t> AsyncTlsSocket::trySend(const void* buf, size_t size) {
    // write to the session
    auto result = m_session->write(buf, size);
    if (result.isErr()) {
        return Err(std::move(result).unwrapErr());
    }

    auto fres = this->tryFlushSync();
    if (fres.isOk()) {
        return Ok(result.unwrap());
    }

    auto err = fres.unwrapErr();
    if (err == TlsError::WANT_WRITE || err == TlsError::WANT_READ) {
        // if we would block, still return success since we already wrote to the session
        return Ok(result.unwrap());
    }

    return Err(std::move(err));
}

Future<TlsResult<size_t>> AsyncTlsSocket::receive(void* buf, size_t size) {
    while (true) {
        // first try to read from the session
        auto result = m_session->read(buf, size);
        if (result.isOk()) {
            co_return Ok(result.unwrap());
        }

        // on error poll until we can read/write and loop again
        auto err = std::move(result).unwrapErr();
        GEODE_CO_UNWRAP(co_await this->handleErr(err));
    }
}

Future<TlsResult<>> AsyncTlsSocket::handleErr(const TlsError& err) {
    while (true) {
        if (err == TlsError::WANT_READ) {
            // always try to flush writes first, this can deadlock otherwise if there's pending data to be sent
            GEODE_CO_UNWRAP(co_await this->flushAll());

            // wait until the socket is readable, then deliver data into the session

            GEODE_CO_UNWRAP(mapResult(co_await this->pollReadable()));

            uint8_t buf[4096];
            auto res = m_stream.receive(buf, sizeof(buf));
            if (res.isErr()) {
                if (res.unwrapErr() == qsox::Error::WouldBlock) {
                    continue;
                }
                co_return Err(TlsError::custom(res.unwrapErr().message()));
            }

            auto recvd = res.unwrap();
            GEODE_CO_UNWRAP(m_session->feedEncryptedData(buf, static_cast<size_t>(recvd)));
            break;
        } else if (err == TlsError::WANT_WRITE) {
            co_return co_await this->flushAll();
        } else {
            co_return Err(std::move(err));
        }
    }

    co_return Ok();
}

Future<TlsResult<>> AsyncTlsSocket::flushAll() {
    while (true) {
        GEODE_CO_UNWRAP_INTO(auto pair, m_session->getEncryptedData());
        auto [edata, esize] = pair;
        if (esize == 0) {
            break;
        }

        auto res = this->tryFlushSync();
        if (!res) {
            auto err = res.unwrapErr();
            if (err == TlsError::WANT_WRITE) {
                GEODE_CO_UNWRAP(mapResult(co_await this->pollWritable()));
                continue;
            }

            co_return Err(std::move(err));
        }
    }

    co_return Ok();
}

TlsResult<> AsyncTlsSocket::tryFlushSync() {
    GEODE_UNWRAP_INTO(auto pair, m_session->getEncryptedData());
    auto [edata, esize] = pair;

    if (esize == 0) {
        return Ok();
    }

    size_t sent = 0;
    while (sent < esize) {
        auto res = m_stream.send(edata + sent, esize - sent);
        if (res.isErr()) {
            auto err = res.unwrapErr();
            if (err == qsox::Error::WouldBlock) {
                break;
            }

            return Err(TlsError::custom(err.message()));
        }

        sent += res.unwrap();
    }

    GEODE_UNWRAP(m_session->notifyEncryptedSent(sent));

    // if we could not send any data, return an error
    if (sent == 0) {
        return Err(TlsError::WANT_WRITE);
    }
    return Ok();
}

}

#endif // XTLS_ENABLE_ARC_SOCKET
