#include <xtls/xtls.hpp>
#include <arc/prelude.hpp>
#include <qsox/Resolver.hpp>
#include <print>

using namespace arc;

// Resolves www.google.com and makes a HTTP/1.1 HTTPS request using AsyncTlsSocket

Future<xtls::TlsResult<>> asyncMainWr() {
    auto& backend = xtls::Backend::get();
    std::println("Using backend {}", backend.description());

    auto context = backend.createContext(xtls::ContextType::Client).unwrap();
    if (!context->loadSystemCACerts()) {
        fmt::println("Failed to load system certs, disabling verification");
        context->setCertVerification(false).unwrap();
    }

    std::println("Resolving www.google.com...");
    auto addrs = co_await arc::spawnBlocking<qsox::IpAddress>([] {
        return qsox::resolver::resolve("www.google.com").unwrap();
    });
    std::println("Resolved address: {}", addrs.toString());

    auto socket = ARC_CO_UNWRAP(
        co_await xtls::AsyncTlsSocket::connect(qsox::SocketAddress{addrs, 443}, context, "www.google.com")
    );

    std::println("Handshake successful!");

    std::string_view req = "HEAD / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    ARC_CO_UNWRAP(co_await socket.send(req.data(), req.size()));

    uint8_t buf[4096];
    while (true) {
        auto res = co_await socket.receive(buf, sizeof(buf));
        if (!res) {
            std::println("Receive error: {}", res.unwrapErr().message);
            break;
        }
        size_t recvd = res.unwrap();
        std::string_view data{reinterpret_cast<char*>(buf), recvd};
        std::print("{}", data);
    }

    co_return Ok();
}

Future<Result<>> asyncMain() {
    auto res = co_await asyncMainWr();
    co_return res.mapErr([](xtls::TlsError e) { return e.message; });
}

ARC_DEFINE_MAIN(asyncMain);