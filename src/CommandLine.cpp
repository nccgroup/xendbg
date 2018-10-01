#include "CommandLine.hpp"
#include "ServerModeController.hpp"

using xd::CommandLine;
using xd::gdb::GDBServer;
using xd::xen::DomID;
using xd::xen::XenException;

CommandLine::CommandLine()
    : _app{"xendbg"}, _port(0)
{
  auto server_mode = _app.add_option(
      "-s,--server", _port,
      "Start as an LLDB stub server on the given port.")
    ->type_name("PORT");

  auto attach = _app.add_option(
      "-a,--attach", _domain,
      "Attach to a single domain given either its domid "
      "or name. If omitted, xendbg will start a server "
      "for each domain on sequential ports starting from "
      "PORT, adding and removing ports as domains start "
      "up and shut down.")
    ->type_name("DOMAIN");

  attach->needs(server_mode);

  _app.callback([this, server_mode, attach] {
    if (server_mode->count()) {
      xd::ServerModeController server(_port);
      if (attach->count()) {
        if (!_domain.empty() &&
            std::all_of(_domain.begin(), _domain.end(),
              [](const auto &c) {
                return std::isdigit(c);
              }))
        {
          server.run_single(std::stoul(_domain));
        } else {
          server.run_single(_domain);
        }
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

