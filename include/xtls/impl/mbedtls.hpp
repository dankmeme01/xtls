#pragma once
#ifdef XTLS_ENABLE_MBEDTLS
#include <xtls/Backend.hpp>
#include <xtls/Context.hpp>
#include <xtls/Session.hpp>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

namespace xtls {

class MbedTLSContext;
class MbedTLSSession;

class MbedTLSBackend : public Backend {
public:
    TlsResult<std::shared_ptr<Context>> createContext(ContextType type) const override;
    TlsError lastError(int code = 0) const override;
    std::string_view name() const override;
    std::string_view version() const override;
    std::string_view description() const override;

    /// Gets the global instance of the MbedTLS backend
    static MbedTLSBackend& get();

private:
    friend class MbedTLSContext;
    friend class MbedTLSSession;
    mbedtls_entropy_context m_entropy;
    mbedtls_ctr_drbg_context m_ctr_drbg;

    MbedTLSBackend();
    ~MbedTLSBackend();
};

class MbedTLSContext : public Context, public std::enable_shared_from_this<MbedTLSContext> {
public:
    MbedTLSContext(bool server);
    ~MbedTLSContext();

    mbedtls_ssl_config* handle() const { return &m_config; }
    void* handle_() const override { return handle(); }

    TlsResult<std::shared_ptr<Session>> createSession() override;
    TlsResult<> setCertVerification(bool verify) override;
    TlsResult<> loadCACerts(const std::filesystem::path& path) override;
    TlsResult<> loadCACertsBlob(std::string_view pemCerts) override;
    TlsResult<> loadSystemCACerts() override;

private:
    friend class MbedTLSBackend;
    mutable mbedtls_ssl_config m_config;
    mbedtls_x509_crt m_ca_chain;
    bool m_caInited = false;
    bool m_server = false;
};

class MbedTLSSession : public Session {
public:
    MbedTLSSession(bool server);
    ~MbedTLSSession();

    mbedtls_ssl_context* handle() const { return &m_ssl; }
    void* handle_() const override { return handle(); }

    TlsResult<> setup(std::shared_ptr<MbedTLSContext> context);

    TlsError lastError(int ret) const override;
    void setHostname(const std::string& hostname) override;
    void setALPN(std::span<const uint8_t> protos) override;
    void setAppData(void* data) override;
    void* getAppData() const override;
    TlsResult<> doHandshake() override;

    TlsResult<size_t> read(void* buf, size_t size) override;
    TlsResult<size_t> write(const void* buf, size_t size) override;

    TlsResult<> feedEncryptedData(const uint8_t* data, size_t size) override;
    TlsResult<std::pair<const uint8_t*, size_t>> getEncryptedData() override;
    TlsResult<> notifyEncryptedSent(size_t bytes) override;

private:
    friend class MbedTLSContext;

    mutable mbedtls_ssl_context m_ssl;
    std::shared_ptr<MbedTLSContext> m_context;
    std::vector<uint8_t> m_rbio, m_wbio;
    std::vector<const char*> m_alpnPtrs;
    std::string m_alpnString;
    bool m_server = false;
    bool m_actualWantRead = true;

    static int readcb(void* ctx, unsigned char* buf, size_t len);
    static int writecb(void* ctx, const unsigned char* buf, size_t len);
};

}

#endif
