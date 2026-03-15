#include <xtls/xtls.hpp>
#include <xtls/impl/openssl.hpp>
#include <xtls/impl/wolfssl.hpp>

using namespace geode;

namespace xtls {

TlsResult<std::shared_ptr<Context>> Backend::createContext(ContextType type) const {
    return Err(TlsError::custom("not implemented"));
}

TlsError Backend::lastError(int code) const {
    return TlsError{0};
}

Backend& Backend::get() {
#ifdef XTLS_ENABLE_OPENSSL
    return OpenSSLBackend::get();
#elif defined(XTLS_ENABLE_WOLFSSL)
    return WolfSSLBackend::get();
#else
    throw std::runtime_error("No TLS backend enabled");
#endif
}

}
