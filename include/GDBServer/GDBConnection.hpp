//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBCONNECTION_HPP
#define XENDBG_GDBCONNECTION_HPP

#include <functional>
#include <memory>

#include <uvw.hpp>

#include "GDBPacketQueue.hpp"
#include "GDBServer/GDBRequest/GDBRequest.hpp"
#include "GDBServer/GDBResponse/GDBResponse.hpp"

namespace xd::gdb {

  class UnknownPacketTypeException : public std::runtime_error {
  public:
    explicit UnknownPacketTypeException(const std::string &data)
        : std::runtime_error(data) {};
  };

  struct GDBPacket;

  class GDBConnection : public std::enable_shared_from_this<GDBConnection> {
  public:
    using OnReceiveFn = std::function<void(GDBConnection&, const req::GDBRequest&)>;
    using OnCloseFn = std::function<void()>;
    using OnErrorFn = std::function<void(const uvw::ErrorEvent&)>;

    explicit GDBConnection(std::shared_ptr<uvw::TcpHandle> tcp);
    ~GDBConnection();

    void enable_error_strings() { _error_strings = true; };
    void disable_ack_mode() { _ack_mode = false; };

    void stop();
    void read(OnReceiveFn on_receive, OnCloseFn on_close, OnErrorFn on_error);

    void send(const rsp::GDBResponse &packet);
    void send_error(uint8_t code, std::string message);

  private:
    std::shared_ptr<uvw::TcpHandle> _tcp;
    GDBPacketQueue _input_queue;
    bool _ack_mode, _is_initializing, _error_strings;
    OnCloseFn _on_close;
    OnErrorFn _on_error;
    OnReceiveFn _on_receive;

    static req::GDBRequest parse_packet(const GDBPacket &packet);
  };

}

#endif //XENDBG_GDBCONNECTION_HPP
