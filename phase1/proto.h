// Record framing shared by the Phase 1 server and client.
//
// Wire format:  [ length : uint32 BE ][ type : uint8 ][ body : length-1 bytes ]
//
// Length-prefixed rather than delimited, so the framing stays binary-safe if the
// body ever carries arbitrary bytes rather than printable text.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace proto {

constexpr uint8_t  VERSION       = 0x01;
constexpr uint16_t DEFAULT_PORT  = 5555;

// Record types. Only REC_APPDATA is emitted; the other two are reserved so that
// adding record kinds later needs no version bump or parser change.
constexpr uint8_t  REC_HANDSHAKE = 0x01;
constexpr uint8_t  REC_APPDATA   = 0x02;
constexpr uint8_t  REC_ALERT     = 0x03;

constexpr size_t   HDR_LEN       = 4;
constexpr size_t   MAX_RECORD    = 16384;   // bytes after the length prefix
constexpr size_t   MAX_PLAINTEXT = 8192;
constexpr size_t   MAX_USERNAME  = 32;

// Blocking I/O, used by the client.
bool send_record(int fd, uint8_t type, const void* body, size_t len);
bool send_text(int fd, uint8_t type, const std::string& s);

enum class Recv { Ok, Closed, Error, Malformed };
Recv recv_record(int fd, uint8_t& type, std::vector<uint8_t>& body);

// Incremental parser, used by the server's non-blocking sockets: feed whatever
// arrived, then drain whole records.
class RecordReader {
public:
    enum class Status { Ok, NeedMore, Malformed };

    void feed(const uint8_t* data, size_t n);
    Status next(uint8_t& type, std::vector<uint8_t>& body);

    size_t buffered() const { return buf_.size() - off_; }

private:
    std::vector<uint8_t> buf_;
    size_t off_ = 0;            // consumed prefix, reclaimed lazily
};

bool set_nonblocking(int fd);

// 1..MAX_USERNAME chars, [A-Za-z0-9_]. Excluding spaces keeps the
// space-delimited grammar unambiguous.
bool valid_username(const std::string& name);

std::string timestamp();                        // ISO-8601 UTC
std::string to_string(const std::vector<uint8_t>& v);

// Splits into at most max_parts; the last part keeps all remaining bytes.
// "MSG bob hi there" with max_parts=3 -> {"MSG", "bob", "hi there"}.
std::vector<std::string> split_n(const std::string& s, char sep, size_t max_parts);

} // namespace proto
