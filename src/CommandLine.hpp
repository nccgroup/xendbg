//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_COMMANDLINE_HPP
#define XENDBG_COMMANDLINE_HPP

#include <CLI/CLI.hpp>

#include "Xen/Common.hpp"

namespace xd {

  class CommandLine {
  public:
    CommandLine();

    int parse(int argc, char **argv);

  private:
    CLI::App _app;
    uint16_t _port;
    std::string _domain;

  private:
    static void start_gdb_server(xen::DomID domid, uint16_t port);
  };

}

#endif //XENDBG_COMMANDLINE_HPP
