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

#include "GDBPacketInterpreter.hpp"
#include "GDBPacketQueue.hpp"
#include "GDBResponsePacket.hpp"
#include "GDBRequestPacket.hpp"

namespace xd::gdbsrv {

  class UnknownPacketTypeException : public std::runtime_error {
  public:
    explicit UnknownPacketTypeException(const std::string &data)
        : std::runtime_error(data) {};
  };

  class GDBServer {
  private:
    struct OutputData {
      size_t ref_count;
      std::string data;
    };

    /*
    struct ClientID {
    public:
      static ClientID All;

      bool operator==(const ClientID &other) {
        return _client == other._client;
      }

      bool operator!=(const ClientID &other) {
        return _client != other._client;
      }

    protected:
      explicit ClientID(uv_stream_t *client)
        : _client(client) {};

      uv_stream_t *get() { return _client; };

    private:
      uv_stream_t *_client;
    };
     */

  public:
    GDBServer(std::string address, uint16_t port);
    ~GDBServer();

    void set_ack_mode(bool enabled) { _ack_mode = enabled; };

    void start();
    void stop();

    void send(const pkt::GDBResponsePacket& packet);

  private:
    static void destroy_stream_context(uv_handle_t *handle) noexcept;
    static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept;
    static bool validate_packet_checksum(const GDBPacket &packet);
    static pkt::GDBRequestPacket parse_packet(const GDBPacket &packet);
    static std::string format_packet(const pkt::GDBResponsePacket &packet);

    void send_raw(std::string s, uv_stream_t *client = nullptr);

  private:
    std::string _address;
    uint16_t _port;
    bool _is_running;
    bool _ack_mode;
    GDBPacketInterpreterInterface &_interpreter;

    uv_loop_t _loop;
    std::unordered_map<uv_stream_t*, GDBPacketQueue> _input_queues;
  };

}

#endif //XENDBG_GDBSERVER_HPP
