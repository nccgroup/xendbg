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
using xd::xen::XenStore;

int main(int argc, char **argv) {
  assert(argc == 3);
  std::string name(argv[2]);

  Debugger dbg;
  XenStore xenstore;
  const auto id = xenstore.get_domid_from_name(name);
  dbg.attach(id);

  std::cout << "Attached to guest #" << id << std::endl;

  GDBStub stub(std::stoi(argv[1]));
  stub.run(dbg);
}
