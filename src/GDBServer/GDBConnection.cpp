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
using xd::uv::UVTimer;

class UnknownPacketTypeException : public std::runtime_error {
public:
  explicit UnknownPacketTypeException(const std::string &data)
      : std::runtime_error(data) {};
};

GDBConnection::GDBConnection(UVLoop &loop, uv_stream_t *connection)
  : _loop(loop), _timer(loop), _connection(connection, &close_connection),
    _ack_mode(true), _is_running(false)
{
  _connection->data = this;
}

GDBConnection::GDBConnection(GDBConnection&& other)
  : _loop(other._loop),
    _timer(std::move(other._timer)),
    _connection(std::move(other._connection)),
    _input_queue(std::move(other._input_queue)),
    _ack_mode(other._ack_mode),
    _is_running(other._is_running),
    _is_initializing(other._is_initializing),
    _on_receive(std::move(other._on_receive)),
    _on_close(std::move(other._on_close)),
    _on_error(std::move(other._on_error)),
    _timers(std::move(other._timers))
{
  if (_connection)
    _connection->data = this;
}

GDBConnection& GDBConnection::operator=(GDBConnection&& other) {
  _loop = std::move(other._loop);
  _timer = std::move(other._timer);
  _connection = std::move(other._connection);
  if (_connection)
    _connection->data = this;
  _input_queue = std::move(other._input_queue);
  _ack_mode = other._ack_mode;
  _is_running = other._is_running;
  _is_initializing = other._is_initializing;
  _on_receive = std::move(other._on_receive);
  _on_close = std::move(other._on_close);
  _on_error = std::move(other._on_error);
  _timers = std::move(other._timers);
  return *this;
}

void GDBConnection::start(OnReceiveFn on_receive, OnCloseFn on_close, OnErrorFn on_error) {
  _is_running = true;
  _is_initializing = true;

  _on_receive = std::move(on_receive);
  _on_close = std::move(on_close);
  _on_error = std::move(on_error);

  // Clean up expired timers
  _timer.start([this]() {
    _timers.erase(std::remove_if(
          _timers.begin(), _timers.end(),
          [](const auto &timer) {
            return !timer.is_running();
          }),
      _timers.end());
    return false;
  }, 100, 100);

  uv_read_start(uv_upcast<uv_stream_t>(_connection.get()), GDBConnection::alloc_buffer,
    [](uv_stream_t *sock, ssize_t nread, const uv_buf_t *buf) {
      const auto self = (GDBConnection*)sock->data;
      //std::cout << "RRCV: " << buf->base << std::endl;

      if (nread <= 0) {
        uv_close(uv_upcast<uv_handle_t>(sock), [](uv_handle_t *close_handle) {
          free(close_handle);
        });
        free(buf->base);

        self->stop();
        self->_on_close();

        if (nread != UV_EOF)
          self->_on_error();

      } else if (self->_is_initializing && nread == 1 && *buf->base == '+') {

        self->send_raw(sock, "+");
        self->_is_initializing = false;
        free(buf->base);

      } else {

        auto data = std::vector<char>(buf->base, buf->base + nread);
        auto &input_queue = self->_input_queue;

        input_queue.append(data);

        free(buf->base);

        while (!input_queue.empty()) {
          const auto raw_packet = input_queue.pop();

          bool valid = validate_packet_checksum(raw_packet);
          //std::cout << "RECV: " << raw_packet.contents << std::endl;

          if (self->_ack_mode)
            self->send_raw(sock, valid ? "+" : "-");

          if (valid) {
            try { // TODO exception handling
              const auto packet = parse_packet(raw_packet);
              self->_on_receive(*self, packet);
            } catch (const UnknownPacketTypeException &e) {
              self->send(pkt::NotSupportedResponse());
              //std::cout << "[!] " << e.what() << std::endl; // TODO
            }
          }
        }
      }
    });
}

void GDBConnection::stop() {
  uv_read_stop(_connection.get());
  _timer.stop();

  _is_running = false;
}

void GDBConnection::send(const pkt::GDBResponsePacket &packet) {
  const auto raw_packet = format_packet(packet);
  send_raw(_connection.get(), raw_packet);
}

UVTimer &GDBConnection::add_timer() {
  _timers.emplace_back(_loop);
  return _timers.back();
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
  //std::cout << "SEND: " << s << std::endl;

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

void GDBConnection::close_connection(uv_stream_t *connection) {
  auto req = new uv_shutdown_t;
  uv_shutdown(req, uv_upcast<uv_stream_t>(connection), [](uv_shutdown_t *req, int status) {
    if (status < 0)
      throw std::runtime_error("Shutdown failed!");

    uv_close(uv_upcast<uv_handle_t>(req->handle), [](uv_handle_t *close_handle) {
      free(close_handle);
    });
    free(req);
  });
}
