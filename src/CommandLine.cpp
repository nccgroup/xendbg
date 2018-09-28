#include "CommandLine.hpp"
#include "ServerModeController.hpp"

using xd::CommandLine;
using xd::gdbsrv::GDBServer;
using xd::xen::DomID;
using xd::xen::XenException;

CommandLine::CommandLine()
    : _app{"xendbg"}, _port(0)
{
  auto server_mode = _app.add_option("-s,--server", _port, "Server.");
  auto attach = _app.add_option("-a,--attach", _domid, "Attach.");

  attach->needs(server_mode);

  _app.callback([this, server_mode, attach] {
    if (server_mode->count()) {
      xd::ServerModeController server(_port);
      if (attach->count()) {
        server.run_single(_domid);
      } else {
        server.run_multi();
      }
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

