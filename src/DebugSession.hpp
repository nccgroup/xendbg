//
// Created by Spencer Michaels on 9/19/18.
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
