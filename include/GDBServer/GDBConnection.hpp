//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBCONNECTION_HPP
#define XENDBG_GDBCONNECTION_HPP

#include <functional>

#include <uv.h>
#include <UV/UVTCP.hpp>

#include "GDBPacketQueue.hpp"
#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"

namespace xd::gdbsrv {

  struct GDBPacket; // TODO

  class GDBConnection {
  public:
    using OnReceiveFn = std::function<void(GDBConnection&, const pkt::GDBRequestPacket&)>;
    using OnCloseFn = std::function<void()>;

    GDBConnection(uv::UVTCP tcp);
    ~GDBConnection() = default;

    GDBConnection(GDBConnection&& other);
    GDBConnection& operator=(GDBConnection&& other);

    GDBConnection(const GDBConnection& other) = delete;
    GDBConnection& operator=(const GDBConnection& other) = delete;

    bool is_running() const { return _tcp.is_reading(); };

    void disable_ack_mode() { _ack_mode = false; };
    void start(OnReceiveFn on_receive, OnCloseFn on_close,
        uv::OnErrorFn on_error);
    void stop();

    void send(const pkt::GDBResponsePacket &packet, uv::OnErrorFn on_error);

  private:
    uv::UVTCP _tcp;
    GDBPacketQueue _input_queue;
    bool _ack_mode, _is_initializing;

    static bool validate_packet_checksum(const GDBPacket &packet);
    static std::string format_packet(const pkt::GDBResponsePacket &packet);
    static pkt::GDBRequestPacket parse_packet(const GDBPacket &packet);
  };

}

#endif //XENDBG_GDBCONNECTION_HPP
