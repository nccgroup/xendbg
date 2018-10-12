//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_SERVERINSTANCEPV_HPP
#define XENDBG_SERVERINSTANCEPV_HPP

#include <optional>

#include <spdlog/spdlog.h>
#include <uvw.hpp>

#include <Globals.hpp>
#include <Debugger/DebuggerHVM.hpp>
#include <Debugger/DebuggerPV.hpp>
#include <GDBServer/GDBServer.hpp>

#include "GDBServer/GDBRequestHandler.hpp"
#include "GDBServer/GDBServer.hpp"

namespace xd {

  class DebugSessionBase {
  public:
    virtual ~DebugSessionBase() = default;
    virtual void run(const std::string& address_str, uint16_t port) = 0;
  };

  template <typename Debugger_t>
  class DebugSession : public DebugSessionBase {
  public:
    template <typename Domain_t, typename... DebuggerArgs_t>
    DebugSession(uvw::Loop &loop, Domain_t domain, DebuggerArgs_t&&... debugger_args)
      : _debugger(std::make_shared<Debugger_t>(
            loop, std::move(domain), std::forward<DebuggerArgs_t>(debugger_args)...)),
        _gdb_server(std::make_shared<gdb::GDBServer>(loop))
    {
    };

    void run(const std::string& address_str, uint16_t port) override {
      const auto on_error = [](auto error) {
        std::cout << "Error: " << error.what() << std::endl;
      };

      _gdb_server->listen(address_str, port,
        [this, on_error](auto &server, auto connection) {
          _debugger->on_stop([connection](auto signal) {
            connection->send(gdb::rsp::StopReasonSignalResponse(signal, 1));
          });

          _debugger->attach();

          _gdb_connection = connection;
          _request_handler.emplace(*_debugger, *_gdb_connection);
          connection->read([this, &server](auto &connection, const auto &packet) {
            try {
              std::visit(*_request_handler, packet);
            } catch (const xen::XenException &e) {
              spdlog::get(LOGNAME_CONSOLE)->error("Error {0:d} ({1:s}): {2:s}", e.get_err(), std::strerror(e.get_err()), e.what());
              connection.send_error(e.get_err(), e.what());
            }
          }, [this]() {
            _debugger->detach();
            _request_handler.reset();
          }, on_error);
        }, on_error);
    }

  private:
    std::shared_ptr<Debugger_t> _debugger;
    std::shared_ptr<gdb::GDBServer> _gdb_server;
    std::shared_ptr<gdb::GDBConnection> _gdb_connection;
    std::optional<gdb::GDBRequestHandler> _request_handler;
  };

  using DebugSessionHVM = DebugSession<dbg::DebuggerHVM>;
  using DebugSessionPV = DebugSession<dbg::DebuggerPV>;

}

#endif //XENDBG_SERVERINSTANCEPV_HPP
