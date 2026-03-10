#pragma once
#include <memory>
#include <xtls/Base.hpp>
#include <filesystem>

namespace xtls {

class Session;

class Context {
public:
    virtual ~Context() = default;
    Context() = default;

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    virtual TlsResult<std::shared_ptr<Session>> createSession();

    virtual TlsResult<> setCertVerification(bool verify);
    virtual TlsResult<> loadCACerts(const std::filesystem::path& path);
    virtual TlsResult<> loadCACertsBlob(std::string_view pemCerts);
    virtual TlsResult<> loadSystemCACerts();

    virtual TlsResult<> loadCertificates(const std::filesystem::path& path);
    virtual TlsResult<> loadCertificatesBlob(std::string_view pemCerts);
};

}
