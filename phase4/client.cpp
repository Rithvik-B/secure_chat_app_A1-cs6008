// Chat client: authenticated client-server channel (Phase 3) plus optional
// end-to-end encryption between clients (Phase 4, /e2e). Two threads -- main
// reads stdin and sends, reader prints what arrives -- so sends are serialised.
// Outgoing messages are echoed locally so a terminal transcript is complete.

#include "proto.h"
#include "session.h"
#include "e2e.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

int          g_sock = -1;
std::string  g_partner;                 // currently selected chat partner
std::string  g_user;                    // my own username
std::mutex   g_out_mu;

sec::Session g_session;
e2e::Manager g_e2e;

// The reader thread now also sends (E2E acks), so the two threads share the
// outer session's send counter and the E2E state; both are protected.
std::mutex   g_send_mu;                 // guards g_session send (tx counter) + socket write
std::mutex   g_e2e_mu;                  // guards g_e2e

void say(const std::string& line)
{
    std::lock_guard<std::mutex> lk(g_out_mu);
    std::cout << line << std::endl;
}

// Leaves without unwinding: the peer thread is blocked in recv() and cannot be
// cancelled portably, so running destructors underneath it would race.
[[noreturn]] void bail(int code)
{
    std::cout.flush();
    if (g_sock >= 0) ::close(g_sock);
    std::_Exit(code);
}

bool send_line(const std::string& line)
{
    if (line.size() > proto::MAX_PLAINTEXT) {
        say("!! message too long (limit " + std::to_string(proto::MAX_PLAINTEXT) + " bytes)");
        return true;                    // not a socket failure
    }
    std::lock_guard<std::mutex> lk(g_send_mu);   // serialise seal + write across threads
    std::vector<uint8_t> ct;
    if (!g_session.seal(line, ct)) {
        say("!! encryption failed");
        return false;
    }
    return proto::send_record(g_sock, proto::REC_APPDATA, ct.data(), ct.size());
}

// Sends a chat message to `to`, transparently E2E-encrypting it (inner layer)
// when an end-to-end session with `to` exists. Returns false only on socket
// failure. The outer send_line still encrypts to the server on top of this.
bool send_msg_to(const std::string& to, const std::string& text)
{
    if (text.rfind("__E2E", 0) == 0) {           // do not let a user forge a tag
        say("!! messages starting with __E2E are reserved");
        return true;
    }
    std::string payload = text;
    bool e2e = false;
    {
        std::lock_guard<std::mutex> lk(g_e2e_mu);
        if (g_e2e.established(to)) {
            std::string enc, err;
            if (!g_e2e.seal(to, text, enc, err)) { say("!! E2E seal failed: " + err); return true; }
            payload = enc;
            e2e = true;
        }
    }
    if (!send_line("MSG " + to + " " + payload)) return false;
    say("you -> " + to + (e2e ? " [e2e]: " : ": ") + text);
    return true;
}

void display(const std::string& line)
{
    auto parts = proto::split_n(line, ' ', 2);
    const std::string& verb = parts[0];
    const std::string  rest = parts.size() > 1 ? parts[1] : std::string();

    if (verb == "FROM") {
        auto m = proto::split_n(rest, ' ', 2);
        const std::string sender = m[0];
        const std::string text   = m.size() > 1 ? m[1] : std::string();

        // Dispatch on the E2E tag. Handshake tags are never shown as chat; a
        // chat tag is decrypted; anything else is plain chat.
        auto has = [&](const char* t){ return text.rfind(t, 0) == 0; };
        if (has(e2e::TAG_INIT)) {
            std::string ack, err, fp;
            bool ok;
            { std::lock_guard<std::mutex> lk(g_e2e_mu);
              ok = g_e2e.on_init(g_user, sender, text.substr(std::strlen(e2e::TAG_INIT)), ack, err);
              if (ok) fp = g_e2e.fingerprint(sender); }
            if (!ok) { say("!! E2E request from " + sender + " failed: " + err); return; }
            if (!send_line("MSG " + sender + " " + ack)) bail(1);
            say("* end-to-end session established with " + sender + " (they requested it), fingerprint " + fp);
        } else if (has(e2e::TAG_ACK)) {
            std::string err, fp;
            bool ok;
            { std::lock_guard<std::mutex> lk(g_e2e_mu);
              ok = g_e2e.on_ack(g_user, sender, text.substr(std::strlen(e2e::TAG_ACK)), err);
              if (ok) fp = g_e2e.fingerprint(sender); }
            if (!ok) { say("!! E2E ack from " + sender + " failed: " + err); return; }
            say("* end-to-end session established with " + sender + ", fingerprint " + fp);
        } else if (has(e2e::TAG_MSG)) {
            std::string pt, err;
            bool ok;
            { std::lock_guard<std::mutex> lk(g_e2e_mu);
              ok = g_e2e.open(sender, text.substr(std::strlen(e2e::TAG_MSG)), pt, err); }
            if (!ok) { say("!! E2E message from " + sender + " rejected: " + err); return; }
            say(sender + " [e2e]> " + pt);
        } else {
            // Plain text. If an E2E session with this peer exists, a plaintext
            // message is a downgrade -- flag it rather than showing it as normal.
            bool downgrade;
            { std::lock_guard<std::mutex> lk(g_e2e_mu); downgrade = g_e2e.established(sender); }
            if (downgrade)
                say("!! WARNING: unencrypted message from " + sender +
                    " while E2E is active: " + text);
            else
                say(sender + "> " + text);
        }
    } else if (verb == "INFO") {
        say("* " + rest);
    } else if (verb == "ERR") {
        say("!! " + rest);
    } else if (verb == "USERS") {
        say(rest.empty() ? "* online: (nobody)" : "* online: " + rest);
    } else if (verb == "OK") {
        say("* logged in as " + rest);
    } else {
        say("? " + line);               // never drop something unrecognised
    }
}

void reader_thread()
{
    uint8_t type;
    std::vector<uint8_t> body;

    for (;;) {
        switch (proto::recv_record(g_sock, type, body)) {
        case proto::Recv::Ok:
            if (type == proto::REC_APPDATA) {
                std::string line;
                if (!g_session.open(body.data(), body.size(), line)) {
                    // Tag mismatch (altered/replayed/reordered): reject, never show.
                    say("!! AES-GCM authentication failed - record rejected");
                    bail(1);
                }
                display(line);
            } else if (type == proto::REC_ALERT) {
                say("!! server alert: " + proto::to_string(body));
                bail(1);
            } else {
                say("!! unexpected record type " + std::to_string(type));
                bail(1);
            }
            break;
        case proto::Recv::Closed:
            say("* server closed the connection");
            bail(0);
        case proto::Recv::Malformed:
            say("!! malformed record from server");
            bail(1);
        case proto::Recv::Error:
            say(std::string("!! socket error: ") + std::strerror(errno));
            bail(1);
        }
    }
}

// Section 1.3: input that matches no command tag is a plain chat message to the
// currently selected user, so an unrecognised /word is sent as text.
void handle_input(const std::string& line)
{
    if (line.empty()) return;

    if (line[0] == '@') {                           // @username [message]
        auto parts = proto::split_n(line.substr(1), ' ', 2);
        const std::string to = parts[0];
        if (to.empty()) { say("!! usage: @username message"); return; }

        g_partner = to;
        if (parts.size() < 2 || parts[1].empty()) {
            say("* now chatting with " + to);
            return;
        }
        if (!send_msg_to(to, parts[1])) bail(1);
        return;
    }

    if (line.rfind("/chat ", 0) == 0) {             // local state only
        std::string to = line.substr(6);
        if (to.empty()) { say("!! usage: /chat username"); return; }
        g_partner = to;
        say("* now chatting with " + to);
        return;
    }

    if (line.rfind("/e2e ", 0) == 0) {              // start end-to-end with a peer
        std::string to = line.substr(5);
        if (to.empty()) { say("!! usage: /e2e username"); return; }
        std::string payload, err;
        bool ok;
        { std::lock_guard<std::mutex> lk(g_e2e_mu); ok = g_e2e.start(g_user, to, payload, err); }
        if (!ok) { say("!! " + err); return; }
        if (!send_line("MSG " + to + " " + payload)) bail(1);
        say("* requesting end-to-end session with " + to + " ...");
        return;
    }

    if (line == "/who") {
        if (!send_line("WHO")) bail(1);
        return;
    }

    if (line == "/quit") {
        send_line("QUIT");
        ::shutdown(g_sock, SHUT_RDWR);
        say("* bye");
        bail(0);
    }

    if (g_partner.empty()) {
        say("!! no chat partner selected — use @username message, or /chat username");
        return;
    }
    if (!send_msg_to(g_partner, line)) bail(1);
}

int connect_to(const std::string& host, uint16_t port)
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { std::perror("socket"); return -1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "invalid server address: " << host << "\n";
        ::close(fd);
        return -1;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("connect");
        ::close(fd);
        return -1;
    }

    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return fd;
}

} // namespace

void usage(const char* argv0)
{
    std::cerr << "usage: " << argv0
              << " <server-ip> <username> [port] --ca FILE [--expect NAME]\n"
              << "  --ca      trusted CA certificate (required)\n"
              << "  --expect  server identity to require (default chatserver.local)\n";
}

int main(int argc, char** argv)
{
    std::vector<std::string> pos;
    std::string ca_path;
    std::string expect = "chatserver.local";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--ca") { if (i + 1 >= argc) { usage(argv[0]); return 2; } ca_path = argv[++i]; }
        else if (a == "--expect") { if (i + 1 >= argc) { usage(argv[0]); return 2; } expect = argv[++i]; }
        else pos.push_back(a);
    }

    if (pos.size() < 2 || pos.size() > 3 || ca_path.empty()) { usage(argv[0]); return 2; }

    const std::string host = pos[0];
    const std::string user = pos[1];
    g_user = user;
    const uint16_t    port = (pos.size() == 3) ? static_cast<uint16_t>(std::stoi(pos[2]))
                                               : proto::DEFAULT_PORT;

    if (!proto::valid_username(user)) {
        std::cerr << "invalid username: 1-" << proto::MAX_USERNAME
                  << " characters, letters/digits/underscore only\n";
        return 2;
    }

    pki::TrustStore ts;
    std::string terr;
    if (!pki::load_trust_store(ca_path, ts, terr)) {
        std::cerr << "error: " << terr << "\n";
        return 1;
    }

    std::signal(SIGPIPE, SIG_IGN);

    g_sock = connect_to(host, port);
    if (g_sock < 0) return 1;

    // Authenticated key agreement: the client validates the server's certificate
    // and its proof of possession before contributing anything. Everything after,
    // the username included, travels encrypted.
    std::string err;
    if (!sec::client_handshake(g_sock, proto::VERSION, ts, expect, g_session, err)) {
        std::cerr << "handshake aborted: " << err << "\n";
        ::close(g_sock);
        return 1;
    }
    std::cout << "server certificate verified (" << expect << "); "
              << "key exchange complete, fingerprint " << g_session.fingerprint() << "\n";

    // Register and wait for the verdict before going interactive, so a rejected
    // username gives one clear error instead of a session that cannot send.
    if (!send_line("LOGIN " + user)) {
        std::cerr << "failed to send LOGIN\n";
        ::close(g_sock);
        return 1;
    }

    uint8_t type;
    std::vector<uint8_t> body;
    if (proto::recv_record(g_sock, type, body) != proto::Recv::Ok ||
        type != proto::REC_APPDATA) {
        std::cerr << "server closed the connection during login\n";
        ::close(g_sock);
        return 1;
    }
    std::string reply;
    if (!g_session.open(body.data(), body.size(), reply)) {
        std::cerr << "AES-GCM authentication failed during login\n";
        ::close(g_sock);
        return 1;
    }
    if (reply.rfind("OK ", 0) != 0) {
        std::cerr << "login rejected: " << reply << "\n";
        ::close(g_sock);
        return 1;
    }

    std::cout << "connected to " << host << ":" << port << " as " << user << "\n"
              << "commands: @user msg | /chat user | /e2e user | /who | /quit\n"
              << "----------------------------------------------------\n";

    std::thread(reader_thread).detach();

    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        handle_input(line);
    }

    send_line("QUIT");                  // stdin EOF (Ctrl-D)
    bail(0);
}
