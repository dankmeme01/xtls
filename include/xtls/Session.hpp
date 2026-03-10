#pragma once
#include <xtls/Base.hpp>
#include <filesystem>

namespace xtls {

class Session {
public:
    virtual ~Session() = default;
    Session() = default;

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    /// Sets the hostname for SNI and certificate verification (client only)
    virtual void setHostname(const std::string& hostname) = 0;

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
};

}
