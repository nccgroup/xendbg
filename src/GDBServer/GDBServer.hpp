//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBSERVER_HPP
#define XENDBG_GDBSERVER_HPP

#include <cstdint>
#include <functional>
#include <queue>
#include <string>
#include <unordered_map>

#include <uv.h>
#include <uvcast.h>

#include "GDBPacketQueue.hpp"
#include "GDBResponsePacket.hpp"
#include "GDBRequestPacket.hpp"

namespace xd::uv {

  class UVLoop {
  public:
    UVLoop() {
      uv_loop_init(_loop);
    }
    ~UVLoop() {
      uv_loop_close(_loop);
    }
    uv_loop_t *get() const { return _loop; };

  private:
    uv_loop_t *_loop;
  };

}

namespace xd::gdbsrv {

  class UnknownPacketTypeException : public std::runtime_error {
  public:
    explicit UnknownPacketTypeException(const std::string &data)
        : std::runtime_error(data) {};
  };

  class GDBServer {
  public:
  private:
    struct ClientContext {
      ClientContext() : ack_mode(true) {};

      GDBPacketQueue input_queue;
      bool ack_mode;
    };

  public:
    class ClientHandle {
    public:
      ClientHandle(GDBServer &server, uv_stream_t *client)
        : _server(server), _client(client) {};

      void disable_ack_mode() const {
        _server._client_contexts.at(_client).ack_mode = false;
      }

      void send(const pkt::GDBResponsePacket &packet) const {
        _server.send(packet, _client);
      };

      void detach() const {
        uv_close(uv_upcast<uv_handle_t>(_client), destroy_stream_context);

        auto &contexts = _server._client_contexts;
        auto found = contexts.find(_client);
        if (found != contexts.end()) {
          contexts.erase(found);
        }
      }

    private:
      GDBServer &_server;
      uv_stream_t *_client;
    };

    using OnReceiveFn = std::function<void(const ClientHandle&,
        const pkt::GDBRequestPacket&)>;

  public:
    GDBServer(const uv::UVLoop &loop, std::string address, uint16_t port);

    void start(OnReceiveFn on_receive);
    void stop();

    void broadcast(const pkt::GDBResponsePacket& packet);

  private:
    static void destroy_stream_context(uv_handle_t *handle) ;
    static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept;
    static bool validate_packet_checksum(const GDBPacket &packet);
    static pkt::GDBRequestPacket parse_packet(const GDBPacket &packet);
    static std::string format_packet(const pkt::GDBResponsePacket &packet);

    void send(const pkt::GDBResponsePacket& packet, uv_stream_t *client);
    void send_raw(std::string s, uv_stream_t *client);

  private:
    const uv::UVLoop &_loop;

    std::string _address;
    uint16_t _port;
    OnReceiveFn _on_receive;

    std::unordered_map<uv_stream_t*, ClientContext> _client_contexts;
  };

}

#endif //XENDBG_GDBSERVER_HPP
