// Phase 1 chat client: plaintext, no encryption.
//
// Two threads, because the client waits on two sources at once:
//   main    -> stdin, parses commands, writes to the socket
//   reader  -> blocks on the socket, prints what arrives
// The socket stays blocking; each thread blocks on its own source. Terminal
// output is serialised so an incoming message cannot interleave mid-line.

#include "proto.h"

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

int         g_sock = -1;
std::string g_partner;                  // currently selected chat partner
std::mutex  g_out_mu;

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
    return proto::send_text(g_sock, proto::REC_APPDATA, line);
}

void display(const std::string& line)
{
    auto parts = proto::split_n(line, ' ', 2);
    const std::string& verb = parts[0];
    const std::string  rest = parts.size() > 1 ? parts[1] : std::string();

    if (verb == "FROM") {
        auto m = proto::split_n(rest, ' ', 2);
        say(m[0] + "> " + (m.size() > 1 ? m[1] : std::string()));
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
                display(proto::to_string(body));
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
        if (!send_line("MSG " + to + " " + parts[1])) bail(1);
        return;
    }

    if (line.rfind("/chat ", 0) == 0) {             // local state only
        std::string to = line.substr(6);
        if (to.empty()) { say("!! usage: /chat username"); return; }
        g_partner = to;
        say("* now chatting with " + to);
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
    if (!send_line("MSG " + g_partner + " " + line)) bail(1);
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

int main(int argc, char** argv)
{
    if (argc < 3 || argc > 4) {
        std::cerr << "usage: " << argv[0] << " <server-ip> <username> [port]\n";
        return 2;
    }

    const std::string host = argv[1];
    const std::string user = argv[2];
    const uint16_t    port = (argc == 4) ? static_cast<uint16_t>(std::stoi(argv[3]))
                                         : proto::DEFAULT_PORT;

    if (!proto::valid_username(user)) {
        std::cerr << "invalid username: 1-" << proto::MAX_USERNAME
                  << " characters, letters/digits/underscore only\n";
        return 2;
    }

    std::signal(SIGPIPE, SIG_IGN);

    g_sock = connect_to(host, port);
    if (g_sock < 0) return 1;

    // Register and wait for the verdict before going interactive, so a rejected
    // username gives one clear error instead of a session that cannot send.
    if (!proto::send_text(g_sock, proto::REC_APPDATA, "LOGIN " + user)) {
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
    if (proto::to_string(body).rfind("OK ", 0) != 0) {
        std::cerr << "login rejected: " << proto::to_string(body) << "\n";
        ::close(g_sock);
        return 1;
    }

    std::cout << "connected to " << host << ":" << port << " as " << user << "\n"
              << "commands: @user message | /chat user | /who | /quit\n"
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
