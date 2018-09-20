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
using xd::gdbsrv::GDBServer;
using xd::xen::DomID;
using xd::xen::XenException;
using xd::xen::XenHandle;

CommandLine::CommandLine()
    : _app{"xendbg"}
{
  auto attach = _app.add_option("-a,--attach", _domain, "Domain to attach to");
  auto port = _app.add_option("-p,--port", _port, "GDB server port.");

  port->needs(attach);

  _app.callback([this, port] {
    if (port->count()) {
      XenHandle xen;

      const auto domains = xen.get_domains();
      const auto domain = std::find_if(domains.begin(), domains.end(), [this](const auto &domain) {
        return (_domain == domain.get_name()) ||
               (_domain == std::to_string(domain.get_domid()));
      });

      if (domain == domains.end())
        throw std::runtime_error("No such domain!");

      start_gdb_server(domain->get_domid(), _port);
    } else {
      // TODO: start REPL
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

void CommandLine::start_gdb_server(DomID domid, uint16_t port) {
  XenHandle xen;
  DebugSessionPV dbg(xen, domid);
  std::cout << "Attached to guest #" << domid << std::endl;

  GDBServer server("127.0.0.1", port);
  server.start([&](const auto &packet) {
    xd::gdbsrv::interpret_packet(dbg, packet, [&](const auto &pkt) {
      server.send(pkt);
    });
  });
}
