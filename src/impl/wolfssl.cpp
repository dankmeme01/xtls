#include <xtls/impl/wolfssl.hpp>
#include "../Util.hpp"

using namespace geode;

namespace xtls {

static TlsError lastError() {
    unsigned long code = wolfSSL_ERR_get_error();

    if (code == 0) {
        return TlsError::custom("Unknown error");
    }

    char buf[512];
    wolfSSL_ERR_error_string_n(code, buf, sizeof(buf));

    return TlsError{static_cast<int64_t>(code), std::string(buf)};
}

TlsResult<> tlsWrap(auto rcode) {
    if (rcode == 1) {
        return Ok();
    } else {
        return Err(lastError());
    }
}


/// Backend

std::string_view WolfSSLBackend::name() const {
    return "wolfSSL";
}

std::string_view WolfSSLBackend::version() const {
    return wolfSSL_lib_version();
}

std::string_view WolfSSLBackend::description() const {
    static std::string desc = "wolfSSL " + std::string(version());
    return desc;
}

WolfSSLBackend::WolfSSLBackend() {}

WolfSSLBackend& WolfSSLBackend::get() {
    static WolfSSLBackend instance;
    return instance;
}

TlsError WolfSSLBackend::lastError(int code) const {
    return ::xtls::lastError();
}

TlsResult<std::shared_ptr<Context>> WolfSSLBackend::createContext(ContextType type) const {
    WOLFSSL_METHOD* meth = nullptr;
    bool server = false;
    switch (type) {
        case ContextType::Client:
        case ContextType::Client1_3: {
            meth = wolfTLS_client_method();
        } break;
        case ContextType::Server:
        case ContextType::Server1_3: {
            meth = wolfTLS_server_method();
            server = true;
        } break;

        // TODO: DTLS not currently supported, will need to enforce a wolfSSL flag for it
        case ContextType::DtlsClient:;
        case ContextType::DtlsServer: {
            return Err(TlsError::custom("Not implemented"));
        } break;
    }

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(meth);
    if (!ctx) {
        return Err(lastError());
    }

    return Ok(std::make_shared<WolfSSLContext>(ctx, server));
}

/// Context

WolfSSLContext::WolfSSLContext(WOLFSSL_CTX* ctx, bool server) {
    m_ctx = ctx;
    m_server = server;

    // Set some reasonable defaults
    wolfSSL_CTX_set_verify(m_ctx, WOLFSSL_VERIFY_PEER, nullptr);
    wolfSSL_CTX_SetMinVersion(m_ctx, WOLFSSL_TLSV1_2);
}

WolfSSLContext::~WolfSSLContext() {
    if (m_ctx) {
        wolfSSL_CTX_free(m_ctx);
    }
}

WOLFSSL_CTX* WolfSSLContext::handle() const {
    return m_ctx;
}

TlsResult<std::shared_ptr<Session>> WolfSSLContext::createSession() {
    WOLFSSL* ssl = wolfSSL_new(m_ctx);
    if (!ssl) {
        return Err(lastError());
    }
    return Ok(std::make_shared<WolfSSLSession>(ssl, m_server));
}

TlsResult<> WolfSSLContext::setCertVerification(bool verify) {
    wolfSSL_CTX_set_verify(m_ctx, verify ? WOLFSSL_VERIFY_PEER : WOLFSSL_VERIFY_NONE, nullptr);
    return Ok();
}

TlsResult<> WolfSSLContext::loadCACerts(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return Err(TlsError::custom("Certificate file does not exist"));
    }

    auto p = pathToString(path);
    if (0 == wolfSSL_CTX_load_verify_locations(m_ctx, p.c_str(), nullptr)) {
        return Err(lastError());
    }

    return Ok();
}

TlsResult<> WolfSSLContext::loadCACertsBlob(std::string_view pemCerts) {
    return tlsWrap(wolfSSL_CTX_load_verify_buffer(
        m_ctx,
        (const unsigned char*)pemCerts.data(),
        (long)pemCerts.size(),
        WOLFSSL_FILETYPE_PEM
    ));
}

TlsResult<> WolfSSLContext::loadSystemCACerts() {
    if (1 != wolfSSL_CTX_set_default_verify_paths(m_ctx)) {
        return Err(lastError());
    }
    return Ok();
}

/// Session

int WolfSSLSession::readcb(WOLFSSL* ssl, char* buf, int size, void* ctx) {
    auto* session = static_cast<WolfSSLSession*>(ctx);
    auto& rbuf = session->m_rbio;

    if (rbuf.empty()) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }

    size_t toRead = std::min<size_t>(size, rbuf.size());
    memcpy(buf, rbuf.data(), toRead);
    rbuf.erase(rbuf.begin(), rbuf.begin() + toRead);

    return static_cast<int>(toRead);
}

int WolfSSLSession::writecb(WOLFSSL* ssl, char* buf, int size, void* ctx) {
    auto* session = static_cast<WolfSSLSession*>(ctx);
    auto& wbuf = session->m_wbio;

    wbuf.insert(wbuf.end(), buf, buf + size);
    return size;
}

WolfSSLSession::WolfSSLSession(WOLFSSL* ssl, bool server) {
    m_ssl = ssl;
    m_server = server;

    wolfSSL_SSLSetIORecv(m_ssl, &readcb);
    wolfSSL_SSLSetIOSend(m_ssl, &writecb);
    wolfSSL_SetIOReadCtx(m_ssl, this);
    wolfSSL_SetIOWriteCtx(m_ssl, this);

    if (m_server) {
        wolfSSL_set_accept_state(m_ssl);
    } else {
        wolfSSL_set_connect_state(m_ssl);
    }
}

WolfSSLSession::~WolfSSLSession() {
    if (m_ssl) {
        wolfSSL_free(m_ssl);
    }
}

WOLFSSL* WolfSSLSession::handle() const {
    return m_ssl;
}

TlsError WolfSSLSession::lastError(int ret) const {
    int err = wolfSSL_get_error(m_ssl, ret);
    switch (err) {
        case WOLFSSL_ERROR_WANT_READ:
            return TlsError::WANT_READ;
        case WOLFSSL_ERROR_WANT_WRITE:
            return TlsError::WANT_WRITE;
        default:
            return ::xtls::lastError();
    }
}

void WolfSSLSession::setHostname(const std::string& hostname) {
    wolfSSL_UseSNI(m_ssl, WOLFSSL_SNI_HOST_NAME, hostname.c_str(), hostname.size());
    wolfSSL_check_domain_name(m_ssl, hostname.c_str());
}

TlsResult<> WolfSSLSession::doHandshake() {
    int ret = wolfSSL_negotiate(m_ssl);
    if (ret == SSL_SUCCESS) {
        return Ok();
    }
    return Err(lastError(ret));
}

TlsResult<size_t> WolfSSLSession::read(void* buf, size_t size) {
    int ret = wolfSSL_read(m_ssl, buf, static_cast<int>(size));
    if (ret > 0) {
        return Ok(static_cast<size_t>(ret));
    }
    return Err(lastError(ret));
}

TlsResult<size_t> WolfSSLSession::write(const void* buf, size_t size) {
    int ret = wolfSSL_write(m_ssl, buf, static_cast<int>(size));
    if (ret > 0) {
        return Ok(static_cast<size_t>(ret));
    }
    return Err(lastError(ret));
}

TlsResult<> WolfSSLSession::feedEncryptedData(const uint8_t* data, size_t size) {
    m_rbio.insert(m_rbio.end(), data, data + size);
    return Ok();
}

TlsResult<std::pair<const uint8_t*, size_t>> WolfSSLSession::getEncryptedData() {
    if (m_wbio.empty()) {
        return Ok(std::make_pair(nullptr, 0));
    }

    return Ok(std::make_pair(reinterpret_cast<const uint8_t*>(m_wbio.data()), static_cast<size_t>(m_wbio.size())));
}

TlsResult<> WolfSSLSession::notifyEncryptedSent(size_t bytes) {
    if (bytes == 0) return Ok();

    if (bytes > m_wbio.size()) {
        return Err(TlsError::custom("Invalid byte count in notifyEncryptedSent"));
    }
    m_wbio.erase(m_wbio.begin(), m_wbio.begin() + bytes);
    return Ok();
}

}
