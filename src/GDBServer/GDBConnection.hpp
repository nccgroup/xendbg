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
    using OnReceiveFn = std::function<void(GDBConnection&, const pkt::GDBRequestPacket&)>;
    using OnCloseFn = std::function<void()>;
    using OnErrorFn = std::function<void()>;

    GDBConnection(uv::UVLoop &loop, uv_stream_t *connection);
    ~GDBConnection() = default;

    GDBConnection(GDBConnection&& other);
    GDBConnection& operator=(GDBConnection&& other);

    GDBConnection(const GDBConnection& other) = delete;
    GDBConnection& operator=(const GDBConnection& other) = delete;

    bool is_running() const { return _is_running; };

    void disable_ack_mode() { _ack_mode = false; };
    void start(OnReceiveFn on_receive, OnCloseFn on_close, OnErrorFn on_error);
    void stop();

    void send(const pkt::GDBResponsePacket &packet);

    uv::UVTimer &add_timer();

  private:
    static void close_connection(uv_stream_t *connection);

    uv::UVLoop &_loop;
    uv::UVTimer _timer;
    std::unique_ptr<uv_stream_t, decltype(&close_connection)> _connection;
    GDBPacketQueue _input_queue;
    bool _ack_mode, _is_running, _is_initializing;
    OnReceiveFn _on_receive;
    OnCloseFn _on_close;
    OnErrorFn _on_error;
    std::vector<uv::UVTimer> _timers;

    static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept;
    static bool validate_packet_checksum(const GDBPacket &packet);
    static std::string format_packet(const pkt::GDBResponsePacket &packet);
    static void send_raw(uv_stream_t *dest, std::string s);
    static pkt::GDBRequestPacket parse_packet(const GDBPacket &packet);
  };

}

#endif //XENDBG_GDBCONNECTION_HPP
