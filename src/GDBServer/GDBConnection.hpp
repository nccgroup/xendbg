//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBCONNECTION_HPP
#define XENDBG_GDBCONNECTION_HPP

#include <functional>

#include <uv.h>

#include "GDBPacketQueue.hpp"
#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"
#include "../UV/UVLoop.hpp"
#include "../UV/UVTimer.hpp"

namespace xd::gdbsrv {

  struct GDBPacket; // TODO

  class GDBConnection {
  public:
    using OnReceiveFn = std::function<void(const pkt::GDBRequestPacket&)>;

    GDBConnection(const uv::UVLoop &loop, uv_stream_t *connection);
    ~GDBConnection();

    GDBConnection(GDBConnection&& other) = default;
    GDBConnection(const GDBConnection& other) = delete;
    GDBConnection& operator=(GDBConnection&& other) = default;
    GDBConnection& operator=(const GDBConnection& other) = delete;

    void disable_ack_mode() { _ack_mode = false; };
    void start(OnReceiveFn on_receive);
    void stop();

    void send(const pkt::GDBResponsePacket &packet);

    void add_timer(uv::UVTimer::OnTickFn on_tick, uint64_t interval);

  private:
    const uv::UVLoop &_loop;
    uv_stream_t *_connection;
    GDBPacketQueue _input_queue;
    bool _ack_mode;
    OnReceiveFn _on_receive;
    std::vector<uv::UVTimer> _timers;

    static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept;
    static bool validate_packet_checksum(const GDBPacket &packet);
    static std::string format_packet(const pkt::GDBResponsePacket &packet);
    static void send_raw(uv_stream_t *dest, std::string s);
    static pkt::GDBRequestPacket parse_packet(const GDBPacket &packet);
  };

}

#endif //XENDBG_GDBCONNECTION_HPP
