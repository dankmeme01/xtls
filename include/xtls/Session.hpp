#pragma once
#include <xtls/Base.hpp>
#include <span>

namespace xtls {

class Session {
public:
    virtual ~Session() = default;
    Session() = default;

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    virtual void* handle_() const = 0;

    /// Sets the hostname for SNI and certificate verification (client only)
    virtual void setHostname(const std::string& hostname) = 0;
    /// Sets the ALPN protocols to offer (client only)
    virtual void setALPN(std::span<const uint8_t> protos) = 0;
    /// Sets a data pointer specific to the application
    virtual void setAppData(void* data) = 0;
    /// Gets the application data pointer
    virtual void* getAppData() const = 0;

    /// Performs the TLS handshake. This must be called before any read or write operations.
    virtual TlsResult<> doHandshake() = 0;

    /// Reads decrypted data from the session into the given buffer.
    /// This does not make any network operations on its own. You are responsible for creating a socket,
    /// and calling `feedEncryptedData` when data arrives, which subsequently causes this function to succeed.
    virtual TlsResult<size_t> read(void* buf, size_t size) = 0;
    /// Writes data to the session from the given buffer. This does not make any network operations on its own.
    /// You are responsible for calling `getEncryptedData`, sending it, and calling `notifyEncryptedSent` with the number of bytes sent.
    virtual TlsResult<size_t> write(const void* buf, size_t size) = 0;

    virtual TlsResult<> feedEncryptedData(const uint8_t* data, size_t size) = 0;
    virtual TlsResult<std::pair<const uint8_t*, size_t>> getEncryptedData() = 0;
    virtual TlsResult<> notifyEncryptedSent(size_t bytes) = 0;

    /// Returns the last error that happened in this session
    virtual TlsError lastError(int ret = 0) const { return TlsError {0}; }
};

}
