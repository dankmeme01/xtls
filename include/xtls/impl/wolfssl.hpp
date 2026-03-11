#pragma once
#ifdef XTLS_ENABLE_WOLFSSL
#include <xtls/Backend.hpp>
#include <xtls/Context.hpp>
#include <xtls/Session.hpp>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

namespace xtls {

class WolfSSLContext;
class WolfSSLSession;

class WolfSSLBackend : public Backend {
public:
    TlsResult<std::shared_ptr<Context>> createContext(ContextType type) const override;

    /// Gets the global instance of the WolfSSL backend
    static WolfSSLBackend& get();

private:
    WolfSSLBackend();
};

class WolfSSLContext : public Context {
public:
    WolfSSLContext(WOLFSSL_CTX* ctx, bool server);
    ~WolfSSLContext();

    WOLFSSL_CTX* handle() const;

    TlsResult<std::shared_ptr<Session>> createSession() override;
    TlsResult<> setCertVerification(bool verify) override;
    TlsResult<> loadCACerts(const std::filesystem::path& path) override;
    TlsResult<> loadCACertsBlob(std::string_view pemCerts) override;

private:
    friend class WolfSSLBackend;
    WOLFSSL_CTX* m_ctx;
    bool m_server = false;
};

class WolfSSLSession : public Session {
public:
    WolfSSLSession(WOLFSSL* ssl, bool server);
    ~WolfSSLSession();

    WOLFSSL* handle() const;

    void setHostname(const std::string& hostname) override;
    TlsResult<> doHandshake() override;

    TlsResult<size_t> read(void* buf, size_t size) override;
    TlsResult<size_t> write(const void* buf, size_t size) override;

    TlsResult<> feedEncryptedData(const uint8_t* data, size_t size) override;
    TlsResult<std::pair<const uint8_t*, size_t>> getEncryptedData() override;
    TlsResult<> notifyEncryptedSent(size_t bytes) override;

private:
    friend class WolfSSLContext;

    WOLFSSL* m_ssl;
    std::vector<uint8_t> m_rbio, m_wbio;
    bool m_server = false;

    TlsError lastError(int ret) const;

    static int readcb(WOLFSSL* ssl, char* buf, int size, void* ctx);
    static int writecb(WOLFSSL* ssl, char* buf, int size, void* ctx);
};

}

#endif
