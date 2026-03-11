#include <xtls/xtls.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <print>

// Tries to connect to a TLS server running on localhost:4433, using plain bsd sockets

int main() {
    auto& backend = xtls::Backend::get();
    std::println("Using backend {}", backend.description());

    auto context = backend.createContext(xtls::ContextType::Client).unwrap();
    context->loadSystemCACerts().unwrap();
    auto session = context->createSession().unwrap();

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect");
        return 1;
    }

    while (true) {
        auto res = session->doHandshake();
        if (res.isOk()) break;

        // try to send data
        auto [edata, esize] = session->getEncryptedData().unwrap();
        if (esize > 0) {
            ssize_t sent = send(s, edata, esize, 0);
            if (sent == -1) {
                perror("send");
                return 1;
            }
            session->notifyEncryptedSent(sent).unwrap();
        }

        auto err = res.unwrapErr();
        if (err == xtls::TlsError::WANT_READ) {
            uint8_t buf[4096];
            ssize_t recvd = recv(s, buf, sizeof(buf), 0);
            if (recvd == -1) {
                perror("recv");
                return 1;
            } else if (recvd == 0) {
                std::println("Connection closed by peer");
                return 0;
            }
            session->feedEncryptedData(buf, static_cast<size_t>(recvd)).unwrap();
        } else if (err != xtls::TlsError::WANT_WRITE) {
            std::println("Handshake failed: {}", err.message);
            return 1;
        }
    }

    std::println("Handshake successful!");

    return 0;
}