//
// Created by Spencer Michaels on 9/20/18.
//

#include <uvcast.h>
#include <numeric>

#include "GDBServer.hpp"
#include "../Util/string.hpp"

using xd::gdbsrv::GDBServer;
using xd::gdbsrv::GDBPacketQueue;
using xd::gdbsrv::pkt::GDBRequestPacket;
using xd::gdbsrv::pkt::GDBResponsePacket;
using xd::util::string::is_prefix;

GDBServer::GDBServer(std::string address, uint16_t port)
    : _address(std::move(address)), _port(port), _is_running(false), _ack_mode(true)
{};

GDBServer::~GDBServer() {
  stop();
}

void GDBServer::start(OnReceiveFn on_receive) {
  _on_receive = std::move(on_receive);
  _is_running = true;

  uv_loop_init(&_loop);
  _loop.data = this;

  auto server = new uv_tcp_t;
  uv_tcp_init(&_loop, server);
  server->data = this;

  struct sockaddr_in address;
  uv_ip4_addr(_address.c_str(), _port, &address);

  uv_tcp_bind(server, (const struct sockaddr *) &address, 0);

    std::cout << "listening" << std::endl;
  int err = uv_listen(uv_upcast<uv_stream_t>(server), 10,
    [](uv_stream_t *server, int status) {
    std::cout << "listened" << std::endl;
      const auto self = (GDBServer*)server->data;

      if (status < 0)
        throw std::runtime_error("Listen failed!");

      auto client = new uv_tcp_t;
      uv_tcp_init(&self->_loop, client);
      client->data = self;

      if (uv_accept(server, uv_upcast<uv_stream_t>(client))) {
        uv_close(uv_upcast<uv_handle_t>(client), destroy_stream_context);
        return;
      }
      self->_packet_queues[uv_upcast<uv_stream_t>(client)] = GDBPacketQueue();

      uv_read_start(uv_upcast<uv_stream_t>(client), alloc_buffer,
        [](uv_stream_t *sock, ssize_t nread, const uv_buf_t *buf) {
          const auto self = (GDBServer*)sock->data;

          if (nread <= 0) {
            uv_close(uv_upcast<uv_handle_t>(sock), destroy_stream_context);
            free(buf->base);
            if (nread != UV_EOF) {
              std::runtime_error("Read failed!");
            }
          } else {
            auto data = std::vector<char>(buf->base, buf->base + nread);
            auto &queue = self->_packet_queues[uv_upcast<uv_stream_t>(sock)];

            queue.enqueue(data);
            free(buf->base);

            for (auto &pair : self->_packet_queues) {
              std::optional<GDBPacket> raw_packet;
              while ((raw_packet = pair.second.dequeue())) {
                bool valid = validate_packet_checksum(*raw_packet);
                std::cout << "RECV: " << raw_packet->contents << std::endl;

                if (self->_ack_mode)
                  self->send_raw(valid ? "+" : "-");

                if (valid) {
                  try { // TODO
                    const auto packet = parse_packet(*raw_packet);
                    self->on_receive(packet); // TODO: exception handling
                  } catch (const xd::gdbsrv::UnknownPacketTypeException &e) {
                    self->send(pkt::NotSupportedResponse());
                    std::cout << e.what() << std::endl;
                  }
                }
              }
            }
          }
        });
    });

  if (err < 0)
    throw std::runtime_error("Listen failed!");

  auto signal = new uv_signal_t;
  uv_signal_init(&_loop, signal);
  signal->data = this;

  uv_signal_start(signal, [](uv_signal_t *signal_handle, int signal) {
    const auto self = (GDBServer*) signal_handle->data;

    std::ignore = signal;
    auto idle = new uv_idle_t;
    uv_idle_init(&self->_loop, idle);
    idle->data = self;

    uv_idle_start(idle, [](uv_idle_t *handle) {
      const auto self = (GDBServer*) handle->data;

      uv_idle_stop(handle);
      uv_close(uv_upcast<uv_handle_t>(handle), [](uv_handle_t *close_handle) {
        free(close_handle);
      });
      uv_stop(&self->_loop);
    });

    uv_signal_stop(signal_handle);
    uv_close(uv_upcast<uv_handle_t>(signal_handle), [](uv_handle_t *close_handle) {
      free(close_handle);
    });
  }, SIGINT);

  uv_run(&_loop, UV_RUN_DEFAULT);

  stop();
}

void GDBServer::stop() {
  if (!_is_running)
    return;

  uv_walk(&_loop, [](uv_handle_t *walk_handle, void *arg) {
    uv_close(walk_handle, [](uv_handle_t *close_handle) {
      free(close_handle);
    });
  }, nullptr);

  uv_run(&_loop, UV_RUN_DEFAULT);

  if (uv_loop_close(&_loop)) {
    throw std::runtime_error("Loop close failed!");
  }
}

void GDBServer::send(const GDBResponsePacket& packet) {
  send_raw(format_packet(packet));
}

void GDBServer::send_raw(std::string s) {
  auto data = new std::string;
  data->swap(s); // TODO: OK?

  uv_buf_t buf;
  buf.base = data->data();
  buf.len = data->size();

  auto wreq = new uv_write_t;
  wreq->data = data;

  for (const auto kv : _packet_queues) {
    const auto client = kv.first;
    uv_write(wreq, client, &buf, 1, [](uv_write_t *req, int s) {
      std::ignore = s;
      free((std::string*)req->data);
      free(req);
    });
  }
}

void GDBServer::destroy_stream_context(uv_handle_t *handle) noexcept {
  if (handle) {
    const auto server = (GDBServer*)handle->data;

    uv_stream_t *stream = uv_downcast<uv_stream_t>(handle);
    const auto found = server->_packet_queues.find(stream);
    if (found != server->_packet_queues.end())
      server->_packet_queues.erase(found);

    free(handle);
  }
}

void GDBServer::alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept {
  std::ignore = h;
  buf->base = (char*) malloc(suggested);
  buf->len = suggested;
}

bool xd::gdbsrv::GDBServer::validate_packet_checksum(const GDBPacket &packet) {
  const auto& contents = packet.contents;
  const auto checksum_calculated = std::accumulate(
      contents.begin(), contents.end(), (uint8_t)0);

  return checksum_calculated == packet.checksum;
}

std::string GDBServer::format_packet(const GDBResponsePacket &packet) {
  const auto& contents = packet.to_string();
  const uint8_t checksum = std::accumulate(
      contents.begin(), contents.end(), (uint8_t)0);

  std::stringstream ss;
  ss << "$" << contents << "#";
  ss << std::hex << std::setfill('0') << std::setw(2);
  ss << (unsigned)checksum;

  return ss.str();
}

GDBRequestPacket GDBServer::parse_packet(const GDBPacket &packet) {
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

void GDBServer::on_receive(const GDBRequestPacket &packet) {
  if (std::holds_alternative<pkt::StartNoAckModeRequest>(packet)) {
    _ack_mode = false;
    send(pkt::OKResponse());
  } else {
    _on_receive(packet);
  }
}
