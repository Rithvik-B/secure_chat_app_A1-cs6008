// MITM proxy. In Phase 2 it read everything; in Phase 3 the victim now validates
// the server's certificate and proof of possession, so the proxy is rejected --
// it can present neither a CA-signed cert nor the matching private key.
// --tamper flips one forwarded byte (only reachable if a handshake succeeds).

#include "proto.h"
#include "session.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

std::ofstream g_log;
std::atomic<bool> g_tamper_armed{false};   // set by --tamper, fires once

void logline(const std::string& s)
{
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    char ts[32];
    std::strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm);
    std::string line = std::string("[") + ts + "] " + s;
    std::cout << line << std::endl;
    if (g_log.is_open()) g_log << line << std::endl;
}

int dial(const std::string& host, uint16_t port)
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); return -1; }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) { ::close(fd); return -1; }
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

int listen_on(const std::string& bind_addr, uint16_t port)
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port   = htons(port);
    if (::inet_pton(AF_INET, bind_addr.c_str(), &a.sin_addr) != 1) { ::close(fd); return -1; }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) { ::close(fd); return -1; }
    if (::listen(fd, 4) < 0) { ::close(fd); return -1; }
    return fd;
}

// Toward the victim, the proxy is the server side of a handshake. It presents
// `cert_der` and signs with `key`; in Phase 3 neither can be made to satisfy the
// victim's validation without the real CA-signed cert and its private key.
bool handshake_as_server(int victim_fd, const std::vector<uint8_t>& cert_der,
                         EVP_PKEY* key, sec::Session& sess)
{
    sec::ServerHandshake hs;
    hs.set_credentials(cert_der, key);
    for (;;) {
        uint8_t type = 0;
        std::vector<uint8_t> body;
        if (proto::recv_record(victim_fd, type, body) != proto::Recv::Ok) return false;
        if (type != proto::REC_HANDSHAKE) return false;

        std::vector<std::vector<uint8_t>> replies;
        std::string err;
        auto st = hs.feed(body.data(), body.size(), replies, err);
        if (st == sec::ServerHandshake::Status::Failed) return false;
        for (const auto& r : replies)
            if (!proto::send_record(victim_fd, proto::REC_HANDSHAKE, r.data(), r.size()))
                return false;
        if (st == sec::ServerHandshake::Status::Done) {
            sess.install(hs.keys(), sec::Role::Server);
            return true;
        }
    }
}

// Reads sealed records off `from`, decrypts them with `from_sess`, logs the
// plaintext, then re-encrypts with `to_sess` and forwards to `to`.
void pump(int from, int to, sec::Session& from_sess, sec::Session& to_sess,
          const std::string& dir)
{
    for (;;) {
        uint8_t type = 0;
        std::vector<uint8_t> body;
        if (proto::recv_record(from, type, body) != proto::Recv::Ok) break;

        if (type != proto::REC_APPDATA) {           // relay anything else as-is
            proto::send_record(to, type, body.data(), body.size());
            continue;
        }

        std::string line;
        if (!from_sess.open(body.data(), body.size(), line)) {
            logline("[" + dir + "] could not decrypt a record (session desync)");
            break;
        }
        logline("[" + dir + "] " + line);           // captured plaintext

        std::vector<uint8_t> re;
        if (!to_sess.seal(line, re)) break;

        // --tamper: corrupt one forwarded chat record (not the login, so the
        // rejected message is a visible one) -> far side's tag check fails.
        bool expected = true;
        if (!re.empty() && line.rfind("MSG ", 0) == 0 &&
            g_tamper_armed.compare_exchange_strong(expected, false)) {
            re[0] ^= 0x01;
            logline("[" + dir + "] TAMPERED one byte of the next record");
        }
        if (!proto::send_record(to, proto::REC_APPDATA, re.data(), re.size())) break;
    }
    ::shutdown(to, SHUT_RDWR);
}

} // namespace

int main(int argc, char** argv)
{
    std::string listen_addr = "0.0.0.0";
    std::string server_host  = "10.10.0.10";
    uint16_t    listen_port  = proto::DEFAULT_PORT;
    uint16_t    server_port  = proto::DEFAULT_PORT;
    std::string log_path     = "mallory.log";
    std::string ca_path, present_cert, present_key;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* n){ if (i + 1 >= argc){ std::cerr<<n<<" needs a value\n"; std::exit(2);} return std::string(argv[++i]); };
        if      (a == "--listen")       listen_addr = need("--listen");
        else if (a == "--listen-port")  listen_port = static_cast<uint16_t>(std::stoi(need("--listen-port")));
        else if (a == "--server")       server_host = need("--server");
        else if (a == "--server-port")  server_port = static_cast<uint16_t>(std::stoi(need("--server-port")));
        else if (a == "--log")          log_path    = need("--log");
        else if (a == "--ca")           ca_path      = need("--ca");
        else if (a == "--present-cert") present_cert = need("--present-cert");
        else if (a == "--present-key")  present_key  = need("--present-key");
        else if (a == "--tamper")       g_tamper_armed = true;
        else { std::cerr << "usage: " << argv[0]
                         << " --ca F --present-cert F --present-key F [--listen A]"
                            " [--server A] [--log F] [--tamper]\n"; return 2; }
    }
    if (ca_path.empty() || present_cert.empty() || present_key.empty()) {
        std::cerr << "error: --ca, --present-cert and --present-key are required\n";
        return 2;
    }

    // The certificate Mallory shows the victim, and the key she signs with. In
    // Phase 3 neither the fake self-signed cert nor a stolen real cert (whose
    // key she lacks) lets her pass the victim's validation.
    pki::ServerCreds present;
    std::string perr;
    if (!pki::load_server_creds(present_cert, present_key, present, perr)) {
        std::cerr << "error: " << perr << "\n"; return 1;
    }
    // Mallory validates the real server normally on her upstream leg (the CA
    // cert is public); that connection is legitimate, she is just a client there.
    pki::TrustStore ts;
    std::string terr;
    if (!pki::load_trust_store(ca_path, ts, terr)) {
        std::cerr << "error: " << terr << "\n"; return 1;
    }

    std::signal(SIGPIPE, SIG_IGN);
    g_log.open(log_path, std::ios::app);

    int lfd = listen_on(listen_addr, listen_port);
    if (lfd < 0) { std::perror("listen"); return 1; }
    logline("MITM proxy up on " + listen_addr + ":" + std::to_string(listen_port) +
            " -> " + server_host + ":" + std::to_string(server_port) +
            (g_tamper_armed ? "  [tamper armed]" : ""));

    for (;;) {
        sockaddr_in peer{};
        socklen_t plen = sizeof peer;
        int victim = ::accept(lfd, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (victim < 0) { if (errno == EINTR) continue; break; }

        char ip[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
        logline("victim connected from " + std::string(ip) + ":" +
                std::to_string(ntohs(peer.sin_port)));

        // Handshake with the victim as the server. In Phase 3 this is where the
        // attack dies: the victim validates the presented certificate and aborts.
        sec::Session vsess, ssess;
        if (!handshake_as_server(victim, present.cert_der, present.key, vsess)) {
            logline("victim rejected the presented certificate -- attack failed");
            ::close(victim);
            continue;
        }
        int upstream = dial(server_host, server_port);
        if (upstream < 0) {
            logline("cannot reach real server");
            ::close(victim);
            continue;
        }
        std::string err;
        if (!sec::client_handshake(upstream, proto::VERSION, ts, "chatserver.local", ssess, err)) {
            logline("handshake with server failed: " + err);
            ::close(victim); ::close(upstream);
            continue;
        }
        logline("two sessions established -- victim-side fp=" + vsess.fingerprint() +
                "  server-side fp=" + ssess.fingerprint());

        std::thread up([&]{ pump(victim, upstream, vsess, ssess, "C->S"); });
        pump(upstream, victim, ssess, vsess, "S->C");
        up.join();

        ::close(victim);
        ::close(upstream);
        logline("victim disconnected");
    }

    ::close(lfd);
    return 0;
}
