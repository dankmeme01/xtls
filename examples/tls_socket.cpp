#include <xtls/xtls.hpp>
#include <print>

// Tries to connect to a TLS server running on localhost:4433, using plain bsd sockets

int main() {
    auto& backend = xtls::OpenSSLBackend::get();
    auto context = backend.createContext(xtls::ContextType::Client).unwrap();
    context->setCertVerification(false).unwrap();

    auto res = xtls::TlsSocket::connect(qsox::SocketAddress::parse("127.0.0.1:4433").unwrap(), context, "localhost");
    if (!res) {
        std::println("Failed to connect: {}", res.unwrapErr().message);
        return 1;
    }

    std::println("Handshake successful!");

    return 0;
}