//
// Created by smichaels on 12/11/18.
//

#include "DebugSession.hpp"

using xd::DebugSession;

DebugSession::DebugSession(uvw::Loop &loop, std::shared_ptr<dbg::Debugger> debugger)
: _debugger(std::move(debugger)),
  _gdb_server(std::make_shared<gdb::GDBServer>(loop))
{
};

DebugSession::~DebugSession() {
  stop();
}

void DebugSession::stop() {
  if (_gdb_connection)
    _gdb_connection->stop();
  if (_gdb_server)
    _gdb_server->stop();
}

void DebugSession::run(const std::string& address_str, uint16_t port, OnErrorFn on_error) {
  _gdb_server->listen(address_str, port,
    [this, on_error](auto &server, auto connection) {
      _gdb_connection = connection;
      _request_handler.emplace(*_debugger, *_gdb_connection);

      _debugger->on_stop([this, connection](auto reason) {
        _request_handler->send_stop_reply(reason);
      });
      _debugger->attach();

      _gdb_connection->read([this, &server](auto &connection, const auto &packet) {
        try {
          std::visit(*_request_handler, packet);
        } catch (const xen::XenException &e) {
          spdlog::get(LOGNAME_CONSOLE)->error("Error {0:d} ({1:s}): {2:s}", e.get_err(), std::strerror(e.get_err()), e.what());
          connection.send_error(e.get_err(), e.what());
        } catch (const dbg::FeatureNotSupportedException &e) {
          spdlog::get(LOGNAME_CONSOLE)->warn("Unsupported feature: {0:s}", e.what());
          connection.send(gdb::rsp::NotSupportedResponse());
        }
      }, [this]() {
        _debugger->detach();
        _request_handler.reset();
      }, on_error);
    }, on_error);
}
