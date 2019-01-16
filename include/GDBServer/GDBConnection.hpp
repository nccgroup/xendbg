//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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

  class GDBPacket;

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
