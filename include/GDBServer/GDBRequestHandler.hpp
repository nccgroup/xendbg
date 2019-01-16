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

#ifndef XENDBG_GDBREQUESTHANDLER_HPP
#define XENDBG_GDBREQUESTHANDLER_HPP

#include <Debugger/Debugger.hpp>
#include <GDBServer/GDBConnection.hpp>
#include <GDBServer/GDBRequest/GDBRequest.hpp>
#include <GDBServer/GDBResponse/GDBResponse.hpp>
#include <Registers/RegistersX86_32.hpp>
#include <Registers/RegistersX86_64.hpp>
#include <Xen/Domain.hpp>

namespace xd::gdb {

  class PacketSizeException : public std::exception {
  public:
    PacketSizeException(size_t actual_size, size_t expected_size)
      : _actual_size(actual_size),_expected_size(expected_size) {}

    size_t get_expected_size() { return _expected_size; };
    size_t get_actual_size() { return _actual_size; };

  private:
    size_t _actual_size;
    size_t _expected_size;
  };

  class WordSizeException : public std::exception {
  public:
    explicit WordSizeException(size_t word_size)
      : _word_size(word_size) {}

    size_t get_word_size() { return _word_size; };

  private:
    size_t _word_size;
  };

  class GDBServer;
  class GDBConnection;

  class GDBRequestHandler {
  public:
    using OnErrorFn = std::function<void(int)>;

    GDBRequestHandler(dbg::Debugger &debugger, GDBConnection &connection)
      : _debugger(debugger), _connection(connection)
    {
    }

    void send_stop_reply(dbg::StopReason reason) const;

    void send_error(uint8_t code, std::string message = "") const {
      _connection.send_error(code, std::move(message));
    }

    void send(const rsp::GDBResponse &packet) const {
      _connection.send(packet);
    }

  private:
    xd::dbg::Debugger &_debugger;
    GDBConnection &_connection;

    std::vector<size_t> get_thread_ids() const;

  public:
    // Default to a "not supported" response
    // Specialize for specific supported packets
    template <typename Packet_t>
    void operator()(const Packet_t &) const {
      send(rsp::NotSupportedResponse());
    };

  };

}

#endif //XENDBG_GDBREQUESTHANDLER_HPP
