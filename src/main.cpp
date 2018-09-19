#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include "Debugger/Debugger.hpp"
#include "GDBStub/GDBStub.hpp"
#include "Util/IndentHelper.hpp"
#include "Xen/XenStore.hpp"

using xd::dbg::Debugger;
using xd::dbg::gdbstub::GDBStub;
using xd::xen::DomID;
using xd::xen::XenException;
using xd::xen::XenStore;

class CommandLine {
public:
  CommandLine()
    : _app{"Xendbg"}, _port(0), _domain{}
  {
    auto attach = _app.add_option("-a,--attach", _domain, "Domain to attach to");
    auto port = _app.add_option("-p,--port", _port, "GDB server port.");

    port->needs(attach);

    _app.callback([this] {
      if (_port) {
        DomID domid;
        try {
          XenStore xenstore;
          domid = xenstore.get_domid_from_name(_domain);
        } catch (const XenException &e) {
          domid = std::stoul(_domain);
        }

        start_gdb_server(domid, _port);
      }
    });
  };

  int parse(int argc, char **argv) {
    try {
      _app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
      return _app.exit(e);
    }

    return 0;
  }

private:
  CLI::App _app;
  uint16_t _port;
  std::string _domain;

private:
  void start_gdb_server(DomID domid, uint16_t port) {
    Debugger dbg;
    dbg.attach(domid);
    std::cout << "Attached to guest #" << domid << std::endl;
    GDBStub stub(port);
    stub.run(dbg);
  }
};

int main(int argc, char **argv) {
  return CommandLine().parse(argc, argv);
}
