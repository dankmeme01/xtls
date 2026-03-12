#pragma once
#include <memory>
#include <xtls/Base.hpp>

namespace xtls {

class Context;

/// Represents a backend for a cryptography or a TLS library. This does not have any configuration or state,
/// it is a single global object that will be used to create actual TLS contexts or perform other crypto operations.
class Backend {
public:
    virtual ~Backend() = default;
    Backend() = default;

    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;

    virtual TlsResult<std::shared_ptr<Context>> createContext(ContextType type) const;
    virtual TlsError lastError(int code = 0) const;

    virtual std::string_view name() const = 0;
    virtual std::string_view version() const = 0;
    virtual std::string_view description() const = 0;

    /// Returns a global instance of one of the enabled TLS backends.
    /// If multiple are enabled, the choice is not strictly defined, but this function is guaranteed to always return the same backend.
    static Backend& get();
};

}