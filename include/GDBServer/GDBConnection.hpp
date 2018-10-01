//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBCONNECTION_HPP
#define XENDBG_GDBCONNECTION_HPP

#include <functional>
#include <memory>

#include <uvw.hpp>

#include "GDBPacketQueue.hpp"
#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"

namespace xd::gdbsrv {

  class UnknownPacketTypeException : public std::runtime_error {
  public:
    explicit UnknownPacketTypeException(const std::string &data)
        : std::runtime_error(data) {};
  };

  struct GDBPacket;

  class GDBConnection : public std::enable_shared_from_this<GDBConnection> {
  public:
    using OnReceiveFn = std::function<void(GDBConnection&, const pkt::GDBRequestPacket&)>;
    using OnCloseFn = std::function<void()>;
    using OnErrorFn = std::function<void(const uvw::ErrorEvent&)>;

    explicit GDBConnection(std::shared_ptr<uvw::TcpHandle> tcp);
    ~GDBConnection() = default;

    void enable_error_strings() { _error_strings = true; };
    void disable_ack_mode() { _ack_mode = false; };

    void read(OnReceiveFn on_receive, OnCloseFn on_close, OnErrorFn on_error);
    void stop();

    void send(const pkt::GDBResponsePacket &packet);
    void send_error(uint8_t code, std::string message);

  private:
    std::shared_ptr<uvw::TcpHandle> _tcp;
    GDBPacketQueue _input_queue;
    bool _ack_mode, _is_initializing, _error_strings;

    static bool validate_packet_checksum(const GDBPacket &packet);
    static std::string format_packet(const pkt::GDBResponsePacket &packet);
    static pkt::GDBRequestPacket parse_packet(const GDBPacket &packet);
  };

}

#endif //XENDBG_GDBCONNECTION_HPP
