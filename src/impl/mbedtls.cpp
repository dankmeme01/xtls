#include <xtls/impl/mbedtls.hpp>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl_ticket.h>
#include "../Util.hpp"
#include <string.h>

using namespace geode;

namespace xtls {

static TlsError lastError(int code) {
    if (code == MBEDTLS_ERR_SSL_WANT_READ) {
        return TlsError::WANT_READ;
    } else if (code == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return TlsError::WANT_WRITE;
    }

    char buf[512];
    mbedtls_strerror(code, buf, sizeof(buf));
    return TlsError{static_cast<int64_t>(code), std::string(buf)};
}

MbedTLSBackend& MbedTLSBackend::get() {
    static MbedTLSBackend backend;
    return backend;
}

MbedTLSBackend::MbedTLSBackend() {
    mbedtls_entropy_init(&m_entropy);
    mbedtls_ctr_drbg_init(&m_ctr_drbg);
    mbedtls_ctr_drbg_seed(&m_ctr_drbg, mbedtls_entropy_func, &m_entropy, nullptr, 0);

    psa_crypto_init();
}

MbedTLSBackend::~MbedTLSBackend() {
    mbedtls_ctr_drbg_free(&m_ctr_drbg);
    mbedtls_entropy_free(&m_entropy);
}

TlsError MbedTLSBackend::lastError(int code) const {
    return ::xtls::lastError(code);
}

std::string_view MbedTLSBackend::name() const {
    return "MbedTLS";
}

std::string_view MbedTLSBackend::version() const {
    return MBEDTLS_VERSION_STRING;
}

std::string_view MbedTLSBackend::description() const {
    static auto desc = "MbedTLS " + std::string(version());
    return desc;
}

TlsResult<std::shared_ptr<Context>> MbedTLSBackend::createContext(ContextType type) const {
    return Ok(std::make_shared<MbedTLSContext>(type == ContextType::Server));
}

// Context

MbedTLSContext::MbedTLSContext(bool server) : m_server(server) {
    mbedtls_ssl_config_init(&m_config);
    mbedtls_ssl_config_defaults(
        &m_config,
        server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    mbedtls_ssl_conf_authmode(&m_config, MBEDTLS_SSL_VERIFY_REQUIRED);

}

MbedTLSContext::~MbedTLSContext() {
    mbedtls_ssl_config_free(&m_config);
}

TlsResult<std::shared_ptr<Session>> MbedTLSContext::createSession() {
    auto session = std::make_shared<MbedTLSSession>(m_server);
    GEODE_UNWRAP(session->setup(this->shared_from_this()));
    return Ok(std::move(session));
}

TlsResult<> MbedTLSContext::setCertVerification(bool verify) {
    mbedtls_ssl_conf_authmode(&m_config, verify ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
    return Ok();
}

TlsResult<> MbedTLSContext::loadCACerts(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return Err(TlsError::custom("Certificate file does not exist"));
    }

    if (m_caInited) {
        mbedtls_x509_crt_free(&m_ca_chain);
    }

    m_caInited = true;
    mbedtls_x509_crt_init(&m_ca_chain);

    auto p = pathToString(path);
    int ret = mbedtls_x509_crt_parse_file(&m_ca_chain, p.c_str());
    if (ret < 0) {
        mbedtls_x509_crt_free(&m_ca_chain);
        m_caInited = false;
        return Err(lastError(ret));
    }

    mbedtls_ssl_conf_ca_chain(&m_config, &m_ca_chain, nullptr);
    return Ok();
}

// mbedtls does not like when the ca blob has other stuff
static std::vector<std::string> filterPemCerts(std::string_view certs) {
    std::vector<std::string> result;

    size_t pos = 0;
    while (true) {
        auto begin = certs.find("-----BEGIN CERTIFICATE-----", pos);
        if (begin == std::string_view::npos) {
            break;
        }
        auto end = certs.find("-----END CERTIFICATE-----", begin);
        if (end == std::string_view::npos) {
            break;
        }
        end += strlen("-----END CERTIFICATE-----");

        result.emplace_back(certs.substr(begin, end - begin));

        pos = end;
    }
    return result;
}

TlsResult<> MbedTLSContext::loadCACertsBlob(std::string_view pemCerts) {
    if (m_caInited) {
        mbedtls_x509_crt_free(&m_ca_chain);
    }

    m_caInited = true;
    mbedtls_x509_crt_init(&m_ca_chain);

    int ret = 0;

    auto filtered = filterPemCerts(pemCerts);
    for (const auto& cert : filtered) {
        if (cert.empty()) {
            continue;
        }

        // the +1 here is because for whatever reason the size should include null terminator
        int r = mbedtls_x509_crt_parse(&m_ca_chain, reinterpret_cast<const uint8_t*>(cert.data()), cert.size() + 1);
        if (r < 0 && ret == 0) {
            ret = r;
        }
    }

    // only return error if no certs were parsed at all
    if (ret < 0 && m_ca_chain.next == nullptr) {
        mbedtls_x509_crt_free(&m_ca_chain);
        m_caInited = false;
        return Err(lastError(ret));
    }

    mbedtls_ssl_conf_ca_chain(&m_config, &m_ca_chain, nullptr);
    return Ok();
}

TlsResult<> MbedTLSContext::loadSystemCACerts() {
    return Err(TlsError::custom("MbedTLS backend does not support loading system CA certificates"));
}

/// Session

MbedTLSSession::MbedTLSSession(bool server) : m_server(server) {
    mbedtls_ssl_init(&m_ssl);
}

MbedTLSSession::~MbedTLSSession() {
    mbedtls_ssl_free(&m_ssl);
}

TlsResult<> MbedTLSSession::setup(std::shared_ptr<MbedTLSContext> context) {
    m_context = context;
    int ret = mbedtls_ssl_setup(&m_ssl, context->handle());
    if (ret != 0) {
        return Err(lastError(ret));
    }

    mbedtls_ssl_set_bio(&m_ssl, this, &writecb, &readcb, nullptr);

    return Ok();
}

TlsError MbedTLSSession::lastError(int ret) const {
    return ::xtls::lastError(ret);
}

void MbedTLSSession::setHostname(const std::string& hostname) {
    mbedtls_ssl_set_hostname(&m_ssl, hostname.c_str());
}

void MbedTLSSession::setALPN(std::span<const uint8_t> protos) {
    std::string scratch;
    scratch.reserve(protos.size() + 1);
    std::vector<const char*> protoPtrs;

    size_t pos = 0;
    while (pos < protos.size()) {
        uint8_t len = protos[pos];
        if (pos + 1 + len > protos.size()) {
            return;
        }

        protoPtrs.push_back(scratch.data() + scratch.size());
        scratch.append(reinterpret_cast<const char*>(protos.data() + pos + 1), len);
        scratch.push_back('\0');

        pos += 1 + len;
    }
    protoPtrs.push_back(nullptr);

    mbedtls_ssl_conf_alpn_protocols(m_context->handle(), protoPtrs.data());

    m_alpnPtrs = std::move(protoPtrs);
    m_alpnString = std::move(scratch);
}

void MbedTLSSession::setAppData(void* data) {
    mbedtls_ssl_set_user_data_p(&m_ssl, data);
}

void* MbedTLSSession::getAppData() const {
    return mbedtls_ssl_get_user_data_p(&m_ssl);
}

TlsResult<> MbedTLSSession::doHandshake() {
    int ret = mbedtls_ssl_handshake(&m_ssl);
    if (ret == 0) {
        // check ssl verify result
        auto r = mbedtls_ssl_get_verify_result(&m_ssl);
        if (r != 0) {
            char vbuf[512];
            mbedtls_x509_crt_verify_info(vbuf, sizeof(vbuf), "  ! ", r);
            return Err(TlsError::custom(std::string("Cert verification failed: ") + vbuf));
        }
        return Ok();
    }

    return Err(lastError(ret));
}

TlsResult<size_t> MbedTLSSession::read(void* buf, size_t size) {
    while (true) {
        int ret = mbedtls_ssl_read(&m_ssl, reinterpret_cast<uint8_t*>(buf), size);
        if (ret > 0) {
            return Ok(static_cast<size_t>(ret));
        } else if (ret == 0) {
            return Err(TlsError::custom("Connection closed"));
        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ && !m_actualWantRead) {
            continue; // try again
        } else if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            continue; // ignore
        }

        return Err(lastError(ret));
    }
}

TlsResult<size_t> MbedTLSSession::write(const void* buf, size_t size) {
    int ret = mbedtls_ssl_write(&m_ssl, reinterpret_cast<const uint8_t*>(buf), size);
    if (ret >= 0) {
        return Ok(static_cast<size_t>(ret));
    }
    return Err(lastError(ret));
}

TlsResult<> MbedTLSSession::feedEncryptedData(const uint8_t* data, size_t size) {
    m_rbio.insert(m_rbio.end(), data, data + size);
    return Ok();
}

TlsResult<std::pair<const uint8_t*, size_t>> MbedTLSSession::getEncryptedData() {
    if (m_wbio.empty()) {
        return Ok(std::make_pair(nullptr, 0));
    }

    return Ok(std::make_pair(m_wbio.data(), m_wbio.size()));
}

TlsResult<> MbedTLSSession::notifyEncryptedSent(size_t bytes) {
    if (bytes == 0) return Ok();

    if (bytes > m_wbio.size()) {
        return Err(TlsError::custom("Invalid byte count in notifyEncryptedSent"));
    }
    m_wbio.erase(m_wbio.begin(), m_wbio.begin() + bytes);
    return Ok();
}

int MbedTLSSession::readcb(void* ctx, unsigned char* buf, size_t len) {
    auto self = static_cast<MbedTLSSession*>(ctx);
    auto& rbuf = self->m_rbio;

    if (rbuf.empty()) {
        self->m_actualWantRead = true;
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    self->m_actualWantRead = false;
    size_t toRead = std::min(len, rbuf.size());
    memcpy(buf, rbuf.data(), toRead);
    rbuf.erase(rbuf.begin(), rbuf.begin() + toRead);

    return static_cast<int>(toRead);
}

int MbedTLSSession::writecb(void* ctx, const unsigned char* buf, size_t len) {
    auto self = static_cast<MbedTLSSession*>(ctx);
    auto& wbuf = self->m_wbio;

    wbuf.insert(wbuf.end(), buf, buf + len);
    return static_cast<int>(len);
}

}
