#pragma once
#include <Geode/Result.hpp>

namespace xtls {

enum class ContextType {
    /// A TLS client context, the TLS version is negotiated in the handshake
    Client,
    /// A TLS server context, the TLS version is negotiated in the handshake
    Server,

    /// A TLS 1.3 client context
    Client1_3,
    /// A TLS 1.3 server context
    Server1_3,

    /// A DTLS client context, the DTLS version is negotiated in the handshake
    DtlsClient,
    /// A DTLS server context, the DTLS version is negotiated in the handshake
    DtlsServer,
};

struct TlsError {
    int64_t code;
    std::string message;

    static TlsError custom(std::string message) {
        return TlsError{XTLS_CODE_BASE, std::move(message)};
    }

    static TlsError lastError(int code = 0);

    bool operator==(const TlsError& other) const {
        return code == other.code;
    }

    static constexpr int64_t XTLS_CODE_BASE = 87400000000000;

    static const TlsError NOT_IMPLEMENTED;
    static const TlsError WANT_READ;
    static const TlsError WANT_WRITE;
};

template <typename T = void>
using TlsResult = geode::Result<T, TlsError>;

}
