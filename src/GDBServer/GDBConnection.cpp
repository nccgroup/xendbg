#include <iostream>
#include <numeric>
#include <stdexcept>

#include "../uvcast.hpp"

#include "GDBConnection.hpp"
#include "../Util/string.hpp"

using uvcast::uv_upcast;
using xd::gdbsrv::GDBConnection;
using xd::gdbsrv::GDBPacket;
using xd::gdbsrv::pkt::GDBRequestPacket;
using xd::gdbsrv::pkt::GDBResponsePacket;
using xd::util::string::is_prefix;
using xd::uv::UVLoop;

class UnknownPacketTypeException : public std::runtime_error {
public:
  explicit UnknownPacketTypeException(const std::string &data)
      : std::runtime_error(data) {};
};

GDBConnection::GDBConnection(const UVLoop &loop, uv_stream_t *connection)
  : _loop(loop), _connection(connection), _ack_mode(true)
{
  _connection->data = this;
}

GDBConnection::~GDBConnection() {
  uv_close(uv_upcast<uv_handle_t>(_connection), [](uv_handle_t *close_handle) {
    free(close_handle);
  });
}

void GDBConnection::start(OnReceiveFn on_receive) {
  _on_receive = std::move(on_receive);

  uv_read_start(uv_upcast<uv_stream_t>(_connection), GDBConnection::alloc_buffer,
    [](uv_stream_t *sock, ssize_t nread, const uv_buf_t *buf) {
      const auto self = (GDBConnection*)sock->data;

      if (nread <= 0) {
        uv_close(uv_upcast<uv_handle_t>(sock), [](uv_handle_t *close_handle) {
          free(close_handle);
        });
        free(buf->base);

        if (nread != UV_EOF)
          throw std::runtime_error("Read failed!");
      } else {
        auto data = std::vector<char>(buf->base, buf->base + nread);
        auto &input_queue = self->_input_queue;

        input_queue.append(data);

        free(buf->base);

        while (!input_queue.empty()) {
          const auto raw_packet = input_queue.pop();

          bool valid = validate_packet_checksum(raw_packet);
          std::cout << "RECV: " << raw_packet.contents << std::endl;

          if (self->_ack_mode)
            self->send_raw(sock, valid ? "+" : "-");

          if (valid) {
            try { // TODO exception handling
              const auto packet = parse_packet(raw_packet);
              self->_on_receive(packet);
            } catch (const UnknownPacketTypeException &e) {
              self->send(pkt::NotSupportedResponse());
              std::cout << "[!] " << e.what() << std::endl; // TODO
            }
          }
        }
      }
    });
}

void GDBConnection::stop() {
  uv_read_stop(_connection);
}

void GDBConnection::send(const pkt::GDBResponsePacket &packet) {
  const auto raw_packet = format_packet(packet);
  send_raw(_connection, raw_packet);
}

void GDBConnection::add_timer(uv::UVTimer::OnTickFn on_tick, uint64_t interval) {
  _timers.emplace_back(_loop);
  _timers.front().start(on_tick, interval); // TODO: detect and cleanup expired timers
}

void GDBConnection::alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept {
  std::ignore = h;
  buf->base = (char*) malloc(suggested);
  buf->len = suggested;
}

bool GDBConnection::validate_packet_checksum(const GDBPacket &packet) {
  const auto& contents = packet.contents;
  const auto checksum_calculated = std::accumulate(
      contents.begin(), contents.end(), (uint8_t)0);

  return checksum_calculated == packet.checksum;
}

std::string GDBConnection::format_packet(const GDBResponsePacket &packet) {
  const auto& contents = packet.to_string();
  const uint8_t checksum = std::accumulate(
      contents.begin(), contents.end(), (uint8_t)0);

  std::stringstream ss;
  ss << "$" << contents << "#";
  ss << std::hex << std::setfill('0') << std::setw(2);
  ss << (unsigned)checksum;

  return ss.str();
}

void GDBConnection::send_raw(uv_stream_t *dest, std::string s) {
  std::cout << "SEND: " << s << std::endl;

  const auto data = new std::string(std::move(s));

  uv_buf_t buf;
  buf.base = data->data();
  buf.len = data->size();

  auto wreq = new uv_write_t;
  wreq->data = data;

  uv_write(wreq, dest, &buf, 1, [](uv_write_t *req, int /*status*/) {
    delete (std::string*) req->data;
    free(req);
  });
}

GDBRequestPacket GDBConnection::parse_packet(const GDBPacket &packet) {
  const auto &contents = packet.contents;

  switch (contents[0]) {
    case 'q':
      if (contents == "qfThreadInfo")
        return pkt::QueryThreadInfoStartRequest(contents);
      else if (contents == "qsThreadInfo")
        return pkt::QueryThreadInfoContinuingRequest(contents);
      else if (contents == "qC")
        return pkt::QueryCurrentThreadIDRequest(contents);
      else if (is_prefix(std::string("qSupported"), contents))
        return pkt::QuerySupportedRequest(contents);
      else if ("qHostInfo" == contents)
        return pkt::QueryHostInfoRequest(contents);
      else if ("qProcessInfo" == contents)
        return pkt::QueryProcessInfoRequest(contents);
      else if (is_prefix(std::string("qRegisterInfo"), contents))
        return pkt::QueryRegisterInfoRequest(contents);
      else if (is_prefix(std::string("qMemoryRegionInfo"), contents))
        return pkt::QueryMemoryRegionInfoRequest(contents);
      break;
    case 'Q':
      if (contents == "QStartNoAckMode")
        return pkt::StartNoAckModeRequest(contents);
      else if (contents == "QThreadSuffixSupported")
        return pkt::QueryThreadSuffixSupportedRequest(contents);
      else if (contents == "QListThreadsInStopReply")
        return pkt::QueryListThreadsInStopReplySupportedRequest(contents);
      break;
    case '?':
      return pkt::StopReasonRequest(contents);
    case 'k':
      return pkt::KillRequest(contents);
    case 'H':
      return pkt::SetThreadRequest(contents);
    case 'p':
      return pkt::RegisterReadRequest(contents);
    case 'P':
      return pkt::RegisterWriteRequest(contents);
    case 'G':
      return pkt::GeneralRegistersBatchWriteRequest(contents);
    case 'g':
      return pkt::GeneralRegistersBatchReadRequest(contents);
    case 'M':
      return pkt::MemoryWriteRequest(contents);
    case 'm':
      return pkt::MemoryReadRequest(contents);
    case 'c':
      return pkt::ContinueRequest(contents);
    case 'C':
      return pkt::ContinueSignalRequest(contents);
    case 's':
      return pkt::StepRequest(contents);
    case 'S':
      return pkt::StepSignalRequest(contents);
    case 'Z':
      return pkt::BreakpointInsertRequest(contents);
    case 'z':
      return pkt::BreakpointRemoveRequest(contents);
    case 'R':
      return pkt::RestartRequest(contents);
    case 'D':
      return pkt::DetachRequest(contents);
  }

  throw UnknownPacketTypeException(contents);
}
