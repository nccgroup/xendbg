//
// Created by Spencer Michaels on 9/19/18.
//

#include "Debugger/DebugSessionPV.hpp"
#include "GDBServer/GDBServer.hpp"
#include "GDBServer/GDBPacketInterpreter.hpp"
#include "Xen/XenHandle.hpp"

#include "CommandLine.hpp"

using xd::CommandLine;
using xd::dbg::DebugSessionPV;
using xd::gdbsrv::interpret_packet;
using xd::gdbsrv::GDBServer;
using xd::xen::DomID;
using xd::xen::XenException;
using xd::xen::XenHandle;

CommandLine::CommandLine()
    : _app{"xendbg"}, _base_port(0)
{
  auto server_mode = _app.add_option("-s,--server", _base_port,
      "Start server with base port.");

  _app.callback([this, server_mode] {
    if (server_mode->count()) {
      XenHandle xen;
      const auto domains = xen.get_domains();

      xd::uv::UVLoop loop;
      auto port = _base_port;
      for (const auto &domain : domains) {
        if (domain.get_domid() != 0)
          start_gdb_server(loop, xen, domain.get_domid(), port++);
      }
    } else {
      // REPL
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

void CommandLine::start_gdb_server(const uv::UVLoop &loop, const XenHandle &xen,
    DomID domid, uint16_t port)
{
  GDBServer server(loop, "127.0.0.1", port);
  DebugSessionPV debugger(xen, domid);
  server.start([&debugger](const auto &client, const auto &packet) {
      interpret_packet(client, packet, debugger);
  });
  std::cout << "Port " << port << ": domain #" << domid << std::endl;
}
