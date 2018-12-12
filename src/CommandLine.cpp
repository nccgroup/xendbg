#include "CommandLine.hpp"
#include "Constants.hpp"
#include "ServerModeController.hpp"

using xd::CommandLine;
using xd::gdb::GDBServer;
using xd::xen::DomID;
using xd::xen::XenException;

CommandLine::CommandLine()
    : _app{APP_NAME_AND_VERSION}, _port(0)
{
  auto non_stop_mode = _app.add_flag(
          "-n,--non-stop-mode",
          "Enable non-stop mode (HVM only), making step, continue, "
          "breakpoints, etc. only apply to current the thread");

  auto server_mode = _app.add_option(
      "-s,--server", _port,
      "Start as an LLDB stub server on the given port. "
      "If omitted, xendbg will run as a standalone REPL.")
    ->type_name("PORT");

  _ip = "127.0.0.1";
  auto server_ip = _app.add_option(
          "-i,--ip", _ip,
          "Start the stub server on the given address.")
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
  server_ip->needs(server_mode);

  _app.callback([this, non_stop_mode, server_mode, server_ip, attach] {
    if (server_mode->count()) {
      xd::ServerModeController server(_ip, _port, non_stop_mode->count() > 0);
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

