//
// Created by Spencer Michaels on 9/19/18.
//

#ifndef XENDBG_COMMANDLINE_HPP
#define XENDBG_COMMANDLINE_HPP

#include <CLI/CLI.hpp>

#include "Xen/Common.hpp"

namespace xd {

  namespace uv {
    class UVLoop;
  }

  namespace xen {
    class XenHandle;
  }

  class CommandLine {
  public:
    CommandLine();

    int parse(int argc, char **argv);

  private:
    CLI::App _app;

  private:
    uint16_t _base_port;
  };

}

#endif //XENDBG_COMMANDLINE_HPP
