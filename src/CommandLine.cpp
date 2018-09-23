//
// Created by Spencer Michaels on 9/19/18.
//

#include "Debugger/DebugSessionPV.hpp"
#include "GDBServer/GDBServer.hpp"
#include "ServerModeController.hpp"

#include "CommandLine.hpp"

using xd::CommandLine;
using xd::dbg::DebugSessionPV;
using xd::gdbsrv::GDBServer;
using xd::xen::DomID;
using xd::xen::XenException;

CommandLine::CommandLine()
    : _app{"xendbg"}, _base_port(0)
{
  auto server_mode = _app.add_option("-s,--server", _base_port,
      "Start server with base port.");

  _app.callback([this, server_mode] {
    if (server_mode->count()) {
      xd::ServerModeController smc(_base_port);
      smc.run();
    } else {
      // TODO
    }
  });
};

int CommandLine::parse(int argc, char **argv) {
  try {
    _app.parse(argc, argv);
  } catch (const CLI::ParseError &e) {
    return _app.exit(e);
  }
  return 0;
}

/*
void CommandLine::start_gdb_server(uv::UVLoop &loop, XenHandle &xen,
    DomID domid, uint16_t port)
{
  DebugSessionPV debugger(xen, domid);

  GDBServer server(loop, "127.0.0.1", port); // TODO: this gets destroyed
  server.start([&](auto &connection) {
    connection.start([&](auto &packet) {
      interpret_packet(debugger, connection, packet);
    });
  });

  std::cout << "Port " << port << ": domain #" << domid << std::endl;
  loop.start(); // TODO
}
*/
