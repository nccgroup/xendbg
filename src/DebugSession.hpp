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

#ifndef XENDBG_DEBUGSESSION_HPP
#define XENDBG_DEBUGSESSION_HPP

#include <optional>

#include <spdlog/spdlog.h>
#include <uvw.hpp>

#include <Globals.hpp>
#include <GDBServer/GDBServer.hpp>

#include "GDBServer/GDBRequestHandler.hpp"
#include "GDBServer/GDBServer.hpp"

namespace xd {

  class DebugSession : public std::enable_shared_from_this<DebugSession> {
  public:
    using OnErrorFn = std::function<void(const uvw::ErrorEvent&)>;

    DebugSession(uvw::Loop &loop, std::shared_ptr<dbg::Debugger> debugger);
    ~DebugSession();

    void stop();
    void run(const std::string& address_str, uint16_t port, OnErrorFn on_error);

  private:
    std::shared_ptr<dbg::Debugger> _debugger;
    std::shared_ptr<gdb::GDBServer> _gdb_server;
    std::shared_ptr<gdb::GDBConnection> _gdb_connection;
    std::optional<gdb::GDBRequestHandler> _request_handler;
  };

}

#endif //XENDBG_DEBUGSESSION_HPP
