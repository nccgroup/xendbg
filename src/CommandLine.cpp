//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include "REPL/DebuggerREPL.hpp"

#include "CommandLine.hpp"
#include "Constants.hpp"
#include "ServerModeController.hpp"

using xd::CommandLine;
using xd::gdb::GDBServer;
using xd::repl::REPL;
using xd::xen::DomID;
using xd::xen::XenException;

CommandLine::CommandLine()
    : _app{APP_NAME_AND_VERSION}, _port(0)
{
  auto non_stop_mode = _app.add_flag(
          "-n,--non-stop-mode",
          "Enable non-stop mode (HVM only), making step, continue, "
          "breakpoints, etc. only apply to the current thread.");

  auto debug = _app.add_flag(
      "-d,--debug",
      "Enable debug logging.");

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

  server_ip->needs(server_mode);

  _app.callback([this, non_stop_mode, server_mode, attach, debug] {
    if (debug->count()) {
      spdlog::get(LOGNAME_CONSOLE)->set_level(spdlog::level::debug);
      spdlog::get(LOGNAME_ERROR)->set_level(spdlog::level::debug);
    }
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
      try {
        dbg::DebuggerREPL repl(non_stop_mode->count() > 0);
        repl.run();
      } catch (const xen::XenException &e) {
        std::cerr << "Xen error: " << e.what() << std::endl;
        exit(1);
      }
    }
    exit(0);
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

