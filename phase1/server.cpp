// Phase 1 relay server: plaintext, no encryption.
//
// Single-threaded poll() loop over non-blocking sockets. Each connection owns
// an inbound RecordReader and an outbound byte queue, so no client can stall
// the server by sending half a record or by refusing to read.
//
// Routing is by username in a map, so more than the two required clients work.
// Every relayed message is logged with its full text.

#include "proto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr size_t MAX_OUT_QUEUE = 1u << 20;      // drop a peer that never reads
constexpr size_t READ_CHUNK    = 4096;

volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

class Logger {
public:
    bool open(const std::string& path)
    {
        file_.open(path, std::ios::app);
        return file_.is_open();
    }

    void log(const std::string& line)
    {
        std::string stamped = "[" + proto::timestamp() + "] " + line;
        std::cout << stamped << std::endl;          // flushed, so tail -f works
        if (file_.is_open()) file_ << stamped << std::endl;
    }

private:
    std::ofstream file_;
};

Logger g_log;

struct Conn {
    int                  fd = -1;
    std::string          peer;                  // "10.10.0.11:54321"
    bool                 registered = false;
    std::string          user;
    proto::RecordReader  reader;
    std::vector<uint8_t> out;
    size_t               out_off = 0;
    bool                 want_close = false;

    size_t pending() const { return out.size() - out_off; }
    std::string label() const { return registered ? user : ("<" + peer + ">"); }
};

std::unordered_map<int, Conn>        g_conns;
std::unordered_map<std::string, int> g_by_name;

// Queues a record; the poll loop writes it when the socket is writable.
void enqueue(Conn& c, uint8_t type, const std::string& payload)
{
    if (payload.size() + 1 > proto::MAX_RECORD) return;

    uint32_t be = htonl(static_cast<uint32_t>(payload.size() + 1));
    const uint8_t* bep = reinterpret_cast<const uint8_t*>(&be);

    c.out.insert(c.out.end(), bep, bep + proto::HDR_LEN);
    c.out.push_back(type);
    c.out.insert(c.out.end(), payload.begin(), payload.end());
}

void send_line(Conn& c, const std::string& line)
{
    enqueue(c, proto::REC_APPDATA, line);
}

// False if the connection should be dropped.
bool flush_out(Conn& c)
{
    while (c.pending() > 0) {
        ssize_t n = ::send(c.fd, c.out.data() + c.out_off, c.pending(), MSG_NOSIGNAL);
        if (n > 0) { c.out_off += static_cast<size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;   // retry on POLLOUT
        return false;
    }

    if (c.out_off == c.out.size()) {
        c.out.clear();
        c.out_off = 0;
    } else if (c.out_off >= proto::MAX_RECORD) {
        c.out.erase(c.out.begin(), c.out.begin() + static_cast<long>(c.out_off));
        c.out_off = 0;
    }
    return c.pending() <= MAX_OUT_QUEUE;
}

void broadcast(const std::string& line, int except_fd)
{
    for (auto& [fd, c] : g_conns) {
        if (fd == except_fd || !c.registered) continue;
        send_line(c, line);
    }
}

void handle_login(Conn& c, const std::string& args)
{
    if (c.registered) {
        send_line(c, "ERR already logged in");
        return;
    }
    if (!proto::valid_username(args)) {
        send_line(c, "ERR invalid username (1-32 chars, letters/digits/underscore)");
        c.want_close = true;
        return;
    }
    if (g_by_name.count(args)) {
        send_line(c, "ERR username taken");
        c.want_close = true;
        return;
    }

    c.registered = true;
    c.user = args;
    g_by_name[args] = c.fd;

    send_line(c, "OK " + args);
    g_log.log("LOGIN " + args + " from " + c.peer);
    broadcast("INFO " + args + " joined", c.fd);
}

void handle_msg(Conn& c, const std::string& args)
{
    // Only two tokens are parsed: the recipient, and everything after it. The
    // text is copied verbatim, never inspected, so the relay stays independent
    // of whatever the clients put in it.
    auto parts = proto::split_n(args, ' ', 2);
    if (parts.size() < 2) {
        send_line(c, "ERR usage: MSG <to> <text>");
        return;
    }
    const std::string& to   = parts[0];
    const std::string& text = parts[1];

    // Resolve first, so a RELAY line means the message was really delivered.
    auto it  = g_by_name.find(to);
    auto dst = (it == g_by_name.end()) ? g_conns.end() : g_conns.find(it->second);

    if (dst == g_conns.end()) {
        g_log.log("UNDELIV " + c.user + " -> " + to + " : \"" + text + "\"");
        send_line(c, "ERR no such user: " + to);
        return;
    }

    g_log.log("RELAY " + c.user + " -> " + to + " : \"" + text + "\"");
    send_line(dst->second, "FROM " + c.user + " " + text);
}

void handle_who(Conn& c)
{
    // Sorted: g_by_name iteration order varies between runs, which would make
    // captured evidence hard to compare.
    std::vector<std::string> names;
    names.reserve(g_by_name.size());
    for (const auto& [name, fd] : g_by_name) { (void)fd; names.push_back(name); }
    std::sort(names.begin(), names.end());

    std::string list;
    for (const auto& n : names) {
        if (!list.empty()) list += " ";
        list += n;
    }

    g_log.log("WHO   " + c.user + " -> [" + list + "]");
    send_line(c, "USERS " + list);
}

bool handle_line(Conn& c, const std::string& line)
{
    auto parts = proto::split_n(line, ' ', 2);
    const std::string verb = parts[0];
    const std::string args = parts.size() > 1 ? parts[1] : std::string();

    if (!c.registered && verb != "LOGIN") {
        send_line(c, "ERR must LOGIN first");
        c.want_close = true;
        return true;
    }

    if      (verb == "LOGIN") handle_login(c, args);
    else if (verb == "MSG")   handle_msg(c, args);
    else if (verb == "WHO")   handle_who(c);
    else if (verb == "QUIT") {
        g_log.log("QUIT  " + c.label());
        c.want_close = true;
    } else {
        send_line(c, "ERR unknown command: " + verb);
    }
    return true;
}

// Dispatches every complete record currently buffered.
bool drain_records(Conn& c)
{
    uint8_t type;
    std::vector<uint8_t> body;

    for (;;) {
        auto st = c.reader.next(type, body);
        if (st == proto::RecordReader::Status::NeedMore) return true;
        if (st == proto::RecordReader::Status::Malformed) {
            g_log.log("DROP  " + c.label() + " : malformed record length");
            return false;
        }
        if (type != proto::REC_APPDATA) {
            g_log.log("DROP  " + c.label() + " : unexpected record type " +
                      std::to_string(type));
            return false;
        }
        if (body.size() > proto::MAX_PLAINTEXT) {
            g_log.log("DROP  " + c.label() + " : payload too large");
            return false;
        }

        if (!handle_line(c, proto::to_string(body))) return false;
        if (c.want_close) return true;
    }
}

bool on_readable(Conn& c)
{
    uint8_t buf[READ_CHUNK];
    for (;;) {
        ssize_t n = ::recv(c.fd, buf, sizeof buf, 0);
        if (n > 0) {
            c.reader.feed(buf, static_cast<size_t>(n));
            if (!drain_records(c)) return false;
            if (c.want_close) return true;
            continue;
        }
        if (n == 0) return false;                                   // peer closed
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;   // drained
        return false;
    }
}

void drop_conn(int fd, const std::string& why)
{
    auto it = g_conns.find(fd);
    if (it == g_conns.end()) return;

    Conn& c = it->second;
    std::string who = c.label();
    if (c.registered) {
        g_by_name.erase(c.user);
        broadcast("INFO " + c.user + " left", fd);
    }
    ::close(fd);
    g_conns.erase(it);
    g_log.log("CLOSE " + who + " (" + why + ")");
}

int make_listener(const std::string& bind_addr, uint16_t port)
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { std::perror("socket"); return -1; }

    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (::inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "invalid bind address: " << bind_addr << "\n";
        ::close(fd);
        return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        std::perror("bind"); ::close(fd); return -1;
    }
    if (::listen(fd, 16) < 0) {
        std::perror("listen"); ::close(fd); return -1;
    }
    if (!proto::set_nonblocking(fd)) {
        std::perror("fcntl"); ::close(fd); return -1;
    }
    return fd;
}

void accept_new(int listen_fd)
{
    for (;;) {
        sockaddr_in peer{};
        socklen_t len = sizeof peer;
        int fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &len);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;    // backlog drained
            // EMFILE/ENFILE leave the connection pending, so poll() reports the
            // listener readable again straight away. Log rather than spin quietly.
            g_log.log(std::string("ACCEPT failed: ") + std::strerror(errno));
            return;
        }

        char ip[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);

        if (!proto::set_nonblocking(fd)) { ::close(fd); continue; }
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

        Conn c;
        c.fd   = fd;
        c.peer = std::string(ip) + ":" + std::to_string(ntohs(peer.sin_port));
        g_log.log("CONN  " + c.peer);
        g_conns.emplace(fd, std::move(c));
    }
}

void usage(const char* argv0)
{
    std::cerr << "usage: " << argv0 << " [--bind ADDR] [--port N] [--log FILE]\n";
}

} // namespace

int main(int argc, char** argv)
{
    std::string bind_addr = "0.0.0.0";
    std::string log_path  = "server.log";
    uint16_t    port      = proto::DEFAULT_PORT;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "--bind" || a == "--port" || a == "--log") && i + 1 >= argc) {
            usage(argv[0]); return 2;
        }
        if      (a == "--bind") bind_addr = argv[++i];
        else if (a == "--port") port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (a == "--log")  log_path = argv[++i];
        else { usage(argv[0]); return 2; }
    }

    // Otherwise a write to a departed peer kills the process.
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    if (!g_log.open(log_path))
        std::cerr << "warning: cannot open " << log_path << ", stdout only\n";

    int listen_fd = make_listener(bind_addr, port);
    if (listen_fd < 0) return 1;

    g_log.log("START phase1 plaintext relay on " + bind_addr + ":" +
              std::to_string(port) + " (log: " + log_path + ")");

    while (!g_stop) {
        std::vector<pollfd> pfds;
        pfds.reserve(g_conns.size() + 1);
        pfds.push_back(pollfd{listen_fd, POLLIN, 0});

        for (auto& [fd, c] : g_conns) {
            short ev = POLLIN;
            if (c.pending() > 0) ev |= POLLOUT;
            pfds.push_back(pollfd{fd, ev, 0});
        }

        int ready = ::poll(pfds.data(), pfds.size(), -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            std::perror("poll");
            break;
        }

        if (pfds[0].revents & POLLIN) accept_new(listen_fd);

        std::vector<std::pair<int, std::string>> doomed;

        for (size_t i = 1; i < pfds.size(); ++i) {
            const int   fd = pfds[i].fd;
            const short re = pfds[i].revents;
            if (re == 0) continue;

            auto it = g_conns.find(fd);
            if (it == g_conns.end()) continue;
            Conn& c = it->second;

            if (re & (POLLERR | POLLNVAL)) { doomed.emplace_back(fd, "socket error"); continue; }
            if ((re & POLLOUT) && !flush_out(c)) { doomed.emplace_back(fd, "write failed"); continue; }
            if ((re & POLLIN)  && !on_readable(c)) { doomed.emplace_back(fd, "peer closed"); continue; }
            if (c.pending() > 0 && !flush_out(c)) { doomed.emplace_back(fd, "write failed"); continue; }
            if (re & POLLHUP) { doomed.emplace_back(fd, "peer hung up"); continue; }
            if (c.want_close && c.pending() == 0) doomed.emplace_back(fd, "quit");
        }

        for (auto& [fd, why] : doomed) drop_conn(fd, why);
    }

    g_log.log("STOP  shutting down");
    for (auto& [fd, c] : g_conns) { (void)c; ::close(fd); }
    ::close(listen_fd);
    return 0;
}
