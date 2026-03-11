#include <xtls/xtls.hpp>
#include <xtls/impl/openssl.hpp>
#include <xtls/impl/wolfssl.hpp>

using namespace geode;

namespace xtls {

TlsResult<std::shared_ptr<Context>> Backend::createContext(ContextType type) const {
    return Err(TlsError::custom("not implemented"));
}

Backend& Backend::get() {
#ifdef XTLS_ENABLE_OPENSSL
    return OpenSSLBackend::get();
#elif defined(XTLS_ENABLE_WOLFSSL)
    return WolfSSLBackend::get();
#else
    static_assert(false, "No TLS backend enabled");
#endif
}

}
