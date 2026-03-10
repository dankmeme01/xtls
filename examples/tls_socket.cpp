#include <xtls/xtls.hpp>
#include <qsox/Resolver.hpp>
#include <print>

// Resolves www.google.com and makes a HTTP/1.1 HTTPS request using TlsSocket

int main() {
    auto& backend = xtls::OpenSSLBackend::get();
    auto context = backend.createContext(xtls::ContextType::Client).unwrap();
    context->setCertVerification(false).unwrap();

    std::println("Resolving www.google.com...");
    auto addrs = qsox::resolver::resolve("www.google.com").unwrap();
    std::println("Resolved address: {}", addrs.toString());

    auto res = xtls::TlsSocket::connect(qsox::SocketAddress{addrs, 443}, context, "www.google.com");
    if (!res) {
        std::println("Failed to connect: {}", res.unwrapErr().message);
        return 1;
    }

    std::println("Handshake successful!");
    auto socket = std::move(res).unwrap();
    std::string_view req = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    socket.send(req.data(), req.size()).unwrap();
    uint8_t buf[4096];

    while (true) {
        auto res = socket.receive(buf, sizeof(buf));
        if (!res) {
            std::println("Receive error: {}", res.unwrapErr().message);
            break;
        }
        size_t recvd = res.unwrap();
        std::string_view data{reinterpret_cast<char*>(buf), recvd};
        std::print("{}", data);
    }

    return 0;
}