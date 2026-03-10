#include <xtls/impl/openssl.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace geode;

namespace xtls {

static TlsError lastError() {
    unsigned long code = ERR_peek_last_error();
    ERR_clear_error();

    if (code == 0) {
        return TlsError::custom("Unknown error");
    }

    char buf[512];
    ERR_error_string_n(code, buf, sizeof(buf));

    return TlsError{static_cast<int64_t>(code), std::string(buf)};
}

TlsResult<> tlsWrap(auto rcode) {
    if (rcode == 1) {
        return Ok();
    } else {
        return Err(lastError());
    }
}

static std::string pathToString(const std::filesystem::path& path) {
#ifdef _WIN32
    auto& wstr = path.native();
    int count = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
    std::string str(count, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
    return str;
#else
    return path.string();
#endif
}

/// Backend

OpenSSLBackend::OpenSSLBackend() {}

OpenSSLBackend& OpenSSLBackend::get() {
    static OpenSSLBackend instance;
    return instance;
}

TlsResult<std::shared_ptr<Context>> OpenSSLBackend::createContext(ContextType type) const {
    const SSL_METHOD* meth = nullptr;
    bool server = false;
    switch (type) {
        case ContextType::Client:
        case ContextType::Client1_3: {
            meth = TLS_client_method();
        } break;
        case ContextType::Server:
        case ContextType::Server1_3: {
            meth = TLS_server_method();
            server = true;
        } break;
        case ContextType::DtlsClient: {
            meth = DTLS_client_method();
        } break;
        case ContextType::DtlsServer: {
            meth = DTLS_server_method();
            server = true;
        } break;
    }

    SSL_CTX* ctx = SSL_CTX_new(meth);
    if (!ctx) {
        return Err(lastError());
    }

    return Ok(std::make_shared<OpenSSLContext>(ctx, server));
}

/// Context

OpenSSLContext::OpenSSLContext(SSL_CTX* ctx, bool server) {
    m_ctx = ctx;
    m_server = server;

    // Set some reasonable defaults
    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);
}

OpenSSLContext::~OpenSSLContext() {
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
    }
}

SSL_CTX* OpenSSLContext::handle() const {
    return m_ctx;
}

TlsResult<std::shared_ptr<Session>> OpenSSLContext::createSession() {
    SSL* ssl = SSL_new(m_ctx);
    if (!ssl) {
        return Err(lastError());
    }
    return Ok(std::make_shared<OpenSSLSession>(ssl, m_server));
}

TlsResult<> OpenSSLContext::setCertVerification(bool verify) {
    SSL_CTX_set_verify(m_ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
    return Ok();
}

TlsResult<> OpenSSLContext::loadCACerts(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return Err(TlsError::custom("Certificate file does not exist"));
    }

    auto p = pathToString(path);
    if (0 == SSL_CTX_load_verify_locations(m_ctx, p.c_str(), nullptr)) {
        return Err(lastError());
    }

    return Ok();
}

TlsResult<> OpenSSLContext::loadCACertsBlob(std::string_view pemCerts) {
    BIO* cbio = BIO_new_mem_buf(pemCerts.data(), static_cast<int>(pemCerts.size()));
    X509* cert = nullptr;
    X509_STORE* store = SSL_CTX_get_cert_store(m_ctx);

    for (size_t i = 0;; i++) {
        PEM_read_bio_X509(cbio, &cert, nullptr, nullptr);
        if (!cert) {
            if (i == 0) {
                BIO_free(cbio);
                return Err(TlsError::custom("Failed to parse any certificates from blob"));
            }
            break;
        }

        if (!X509_STORE_add_cert(store, cert)) {
            X509_free(cert);
            BIO_free(cbio);
            return Err(lastError());
        }

        X509_free(cert);
    }

    BIO_free(cbio);
    return Ok();
}

/// Session

OpenSSLSession::OpenSSLSession(SSL* ssl, bool server) {
    m_ssl = ssl;
    m_server = server;
    m_rbio = BIO_new(BIO_s_mem());
    m_wbio = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(m_rbio, -1);
    BIO_set_mem_eof_return(m_wbio, -1);
    SSL_set_bio(m_ssl, m_rbio, m_wbio);

    if (m_server) {
        SSL_set_accept_state(m_ssl);
    } else {
        SSL_set_connect_state(m_ssl);
    }
}

OpenSSLSession::~OpenSSLSession() {
    if (m_ssl) {
        SSL_free(m_ssl);
    }
}

SSL* OpenSSLSession::handle() const {
    return m_ssl;
}

TlsError OpenSSLSession::lastError(int ret) const {
    int err = SSL_get_error(m_ssl, ret);
    switch (err) {
        case SSL_ERROR_WANT_READ:
            return TlsError::WANT_READ;
        case SSL_ERROR_WANT_WRITE:
            return TlsError::WANT_WRITE;
        default:
            return ::xtls::lastError();
    }
}

void OpenSSLSession::setHostname(const std::string& hostname) {
    SSL_set_tlsext_host_name(m_ssl, hostname.c_str());
    SSL_set1_host(m_ssl, hostname.c_str());
}

TlsResult<> OpenSSLSession::doHandshake() {
    int ret = SSL_do_handshake(m_ssl);
    if (ret == 1) {
        return Ok();
    }
    return Err(lastError(ret));
}

TlsResult<size_t> OpenSSLSession::read(void* buf, size_t size) {
    int ret = SSL_read(m_ssl, buf, static_cast<int>(size));
    if (ret > 0) {
        return Ok(static_cast<size_t>(ret));
    }
    return Err(lastError(ret));
}

TlsResult<size_t> OpenSSLSession::write(const void* buf, size_t size) {
    int ret = SSL_write(m_ssl, buf, static_cast<int>(size));
    if (ret > 0) {
        return Ok(static_cast<size_t>(ret));
    }
    return Err(lastError(ret));
}

TlsResult<> OpenSSLSession::feedEncryptedData(const uint8_t* data, size_t size) {
    int ret = BIO_write(m_rbio, data, static_cast<int>(size));
    if (ret <= 0) {
        return Err(TlsError::custom("Failed to write to rbio"));
    }
    return Ok();
}

TlsResult<std::pair<const uint8_t*, size_t>> OpenSSLSession::getEncryptedData() {
    char* data;
    long size = BIO_get_mem_data(m_wbio, &data);

    if (size <= 0) {
        return Ok(std::make_pair(nullptr, 0));
    }
    return Ok(std::make_pair(reinterpret_cast<const uint8_t*>(data), static_cast<size_t>(size)));
}

TlsResult<> OpenSSLSession::notifyEncryptedSent(size_t bytes) {
    if (bytes == 0) return Ok();

    uint8_t buf[2048];
    size_t rem = bytes;

    while (rem > 0) {
        size_t toRead = std::min(rem, sizeof(buf));
        int ret = BIO_read(m_wbio, buf, static_cast<int>(toRead));
        if (ret <= 0) return Err(TlsError::custom("Failed to read from wbio"));
        rem -= ret;
    }
    return Ok();
}

}
