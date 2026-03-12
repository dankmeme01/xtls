#pragma once
#ifdef XTLS_ENABLE_OPENSSL
#include <openssl/ssl.h>
#include <xtls/Backend.hpp>
#include <xtls/Context.hpp>
#include <xtls/Session.hpp>

namespace xtls {

class OpenSSLContext;
class OpenSSLSession;

class OpenSSLBackend : public Backend {
public:
    TlsResult<std::shared_ptr<Context>> createContext(ContextType type) const override;
    TlsError lastError(int code = 0) const override;
    std::string_view name() const override;
    std::string_view version() const override;
    std::string_view description() const override;

    /// Gets the global instance of the OpenSSL backend
    static OpenSSLBackend& get();

private:
    OpenSSLBackend();
};

class OpenSSLContext : public Context {
public:
    OpenSSLContext(SSL_CTX* ctx, bool server);
    ~OpenSSLContext();

    SSL_CTX* handle() const;
    void* handle_() const override { return handle(); }

    TlsResult<std::shared_ptr<Session>> createSession() override;
    TlsResult<> setCertVerification(bool verify) override;
    TlsResult<> loadCACerts(const std::filesystem::path& path) override;
    TlsResult<> loadCACertsBlob(std::string_view pemCerts) override;
    TlsResult<> loadSystemCACerts() override;

private:
    friend class OpenSSLBackend;
    SSL_CTX* m_ctx;
    bool m_server = false;
};

class OpenSSLSession : public Session {
public:
    OpenSSLSession(SSL* ssl, bool server);
    ~OpenSSLSession();

    SSL* handle() const;
    void* handle_() const override { return handle(); }

    TlsError lastError(int ret) const override;
    void setHostname(const std::string& hostname) override;
    TlsResult<> doHandshake() override;

    TlsResult<size_t> read(void* buf, size_t size) override;
    TlsResult<size_t> write(const void* buf, size_t size) override;

    TlsResult<> feedEncryptedData(const uint8_t* data, size_t size) override;
    TlsResult<std::pair<const uint8_t*, size_t>> getEncryptedData() override;
    TlsResult<> notifyEncryptedSent(size_t bytes) override;

private:
    friend class OpenSSLContext;
    SSL* m_ssl;
    BIO* m_rbio;
    BIO* m_wbio;
    bool m_server = false;

};

}

#endif