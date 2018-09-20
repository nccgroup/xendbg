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
    using OnReceiveFn = std::function<void(pkt::GDBRequestPacket)>;

  public:
    GDBServer(std::string address, uint16_t port);
    ~GDBServer();

    void start(OnReceiveFn on_receive);
    void stop();

    void send(pkt::GDBResponsePacket packet);

  private:
    static void destroy_stream_context(uv_handle_t *handle) noexcept;
    static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept;
    static bool validate_packet_checksum(const GDBPacket &packet);
    static pkt::GDBRequestPacket parse_packet(const GDBPacket &packet);
    static std::string format_packet(const pkt::GDBResponsePacket &packet);

  private:
    std::string _address;
    uint16_t _port;
    OnReceiveFn _on_receive;
    bool _is_running;

    uv_loop_t _loop;
    std::unordered_map<uv_stream_t*, GDBPacketQueue> _packet_queues;
  };

}

#endif //XENDBG_GDBSERVER_HPP
