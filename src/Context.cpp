#include <xtls/Context.hpp>
using namespace geode;

namespace xtls {

TlsResult<std::shared_ptr<Session>> Context::createSession() {
    return Err(TlsError::NOT_IMPLEMENTED);
}
TlsResult<> Context::setCertVerification(bool verify) {
    return Err(TlsError::NOT_IMPLEMENTED);
}
TlsResult<> Context::loadCACerts(const std::filesystem::path& path) {
    return Err(TlsError::NOT_IMPLEMENTED);
}
TlsResult<> Context::loadCACertsBlob(std::string_view pemCerts) {
    return Err(TlsError::NOT_IMPLEMENTED);
}
TlsResult<> Context::loadSystemCACerts() {
    return Err(TlsError::NOT_IMPLEMENTED);
}
TlsResult<> Context::loadCertificates(const std::filesystem::path& path) {
    return Err(TlsError::NOT_IMPLEMENTED);
}
TlsResult<> Context::loadCertificatesBlob(std::string_view pemCerts) {
    return Err(TlsError::NOT_IMPLEMENTED);
}

}