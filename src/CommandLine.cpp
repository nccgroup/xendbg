//
// Created by Spencer Michaels on 9/19/18.
//

#include <Debugger/DebugSessionPV.hpp>
#include <GDBServer/GDBServer.hpp>
#include "Server/Server.hpp"

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
      xd::Server server(_base_port);
      server.run();
    } else {
      // TODO: repl mode
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

