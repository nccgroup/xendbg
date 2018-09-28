#include <GDBServer/GDBPacketHandler.hpp>

#include "DebugSessionPV.hpp"

using xd::DebugSessionPV;
using xd::dbg::DebuggerPV;
using xd::gdbsrv::GDBServer;

DebugSessionPV::DebugSessionPV(uvw::Loop &loop, xen::DomainPV domain)
  : _domain(std::move(domain)),
    _debugger(std::make_shared<DebuggerPV>(loop, _domain)),
    _gdb_server(std::make_shared<GDBServer>(loop))
{
};

void DebugSessionPV::run(const std::string& address_str, uint16_t port) {
  const auto on_error = [](auto error) {
    std::cout << "Error: " << error.what() << std::endl;
  };

  _gdb_server->listen(address_str, port,
    [this, on_error](auto &server, auto connection) {
      _gdb_connection = connection;
      _debugger->attach();

      _packet_handler.emplace(_domain, *_debugger, *_gdb_server, *_gdb_connection);
      connection->read([this, &server](auto &connection, const auto &packet) {
        std::visit(*_packet_handler, packet);
      }, [this]() {
        _debugger->detach();
        _packet_handler.reset();
      }, on_error);
    }, on_error);
}
