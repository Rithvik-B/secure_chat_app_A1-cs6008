#include "proto.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>

namespace proto {

namespace {

// send() may write fewer bytes than asked. MSG_NOSIGNAL turns a write to a
// dead peer into EPIPE instead of SIGPIPE.
bool send_all(int fd, const uint8_t* buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) { sent += static_cast<size_t>(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

// recv() may return fewer bytes than asked; 0 means an orderly shutdown.
Recv recv_all(int fd, uint8_t* buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = ::recv(fd, buf + got, len - got, 0);
        if (n > 0) { got += static_cast<size_t>(n); continue; }
        if (n == 0) return Recv::Closed;
        if (errno == EINTR) continue;
        return Recv::Error;
    }
    return Recv::Ok;
}

} // namespace

bool send_record(int fd, uint8_t type, const void* body, size_t len)
{
    if (len + 1 > MAX_RECORD) return false;

    std::vector<uint8_t> rec;
    rec.reserve(HDR_LEN + 1 + len);

    uint32_t be = htonl(static_cast<uint32_t>(len + 1));   // +1 for the type byte
    const uint8_t* bep = reinterpret_cast<const uint8_t*>(&be);
    rec.insert(rec.end(), bep, bep + HDR_LEN);
    rec.push_back(type);

    const uint8_t* b = static_cast<const uint8_t*>(body);
    rec.insert(rec.end(), b, b + len);

    // One write for the whole record, so a dying peer cannot leave a header
    // on the wire without its body.
    return send_all(fd, rec.data(), rec.size());
}

bool send_text(int fd, uint8_t type, const std::string& s)
{
    return send_record(fd, type, s.data(), s.size());
}

Recv recv_record(int fd, uint8_t& type, std::vector<uint8_t>& body)
{
    uint8_t hdr[HDR_LEN];
    Recv r = recv_all(fd, hdr, HDR_LEN);
    if (r != Recv::Ok) return r;

    uint32_t len;
    std::memcpy(&len, hdr, HDR_LEN);
    len = ntohl(len);

    // Never allocate on an untrusted length.
    if (len < 1 || len > MAX_RECORD) return Recv::Malformed;

    std::vector<uint8_t> buf(len);
    r = recv_all(fd, buf.data(), len);
    if (r != Recv::Ok) return r;

    type = buf[0];
    body.assign(buf.begin() + 1, buf.end());
    return Recv::Ok;
}

void RecordReader::feed(const uint8_t* data, size_t n)
{
    if (off_ > 0) {
        if (off_ == buf_.size()) {
            buf_.clear();
            off_ = 0;
        } else if (off_ >= MAX_RECORD) {          // worth the memmove now
            buf_.erase(buf_.begin(), buf_.begin() + static_cast<long>(off_));
            off_ = 0;
        }
    }
    buf_.insert(buf_.end(), data, data + n);
}

RecordReader::Status RecordReader::next(uint8_t& type, std::vector<uint8_t>& body)
{
    size_t avail = buf_.size() - off_;
    if (avail < HDR_LEN) return Status::NeedMore;

    uint32_t len;
    std::memcpy(&len, buf_.data() + off_, HDR_LEN);
    len = ntohl(len);

    if (len < 1 || len > MAX_RECORD) return Status::Malformed;
    if (avail < HDR_LEN + len) return Status::NeedMore;

    const size_t start = off_ + HDR_LEN;
    type = buf_[start];
    body.assign(buf_.begin() + static_cast<long>(start) + 1,
                buf_.begin() + static_cast<long>(start + len));

    off_ += HDR_LEN + len;
    if (off_ == buf_.size()) {
        buf_.clear();
        off_ = 0;
    }
    return Status::Ok;
}

bool set_nonblocking(int fd)
{
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool valid_username(const std::string& name)
{
    if (name.empty() || name.size() > MAX_USERNAME) return false;
    for (unsigned char c : name) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

std::string timestamp()
{
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string to_string(const std::vector<uint8_t>& v)
{
    return std::string(v.begin(), v.end());
}

std::vector<std::string> split_n(const std::string& s, char sep, size_t max_parts)
{
    std::vector<std::string> out;
    if (max_parts == 0) return out;

    size_t pos = 0;
    while (out.size() + 1 < max_parts) {
        size_t hit = s.find(sep, pos);
        if (hit == std::string::npos) break;
        out.push_back(s.substr(pos, hit - pos));
        pos = hit + 1;
    }
    out.push_back(s.substr(pos));
    return out;
}

} // namespace proto
