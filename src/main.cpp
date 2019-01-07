#include <spdlog/spdlog.h>
#include <uvw.hpp>

#include <Globals.hpp>

#include "CommandLine.hpp"

using xd::CommandLine;

int main(int argc, char **argv) {
  auto console = spdlog::stdout_color_mt(LOGNAME_CONSOLE);
  console->set_level(spdlog::level::info);
  console->set_pattern("[%H:%M:%S.%e] %v");

  auto err_log = spdlog::stderr_color_mt(LOGNAME_ERROR);
  err_log->set_level(spdlog::level::err);
  err_log->set_pattern("[%H:%M:%S.%e] [%L] %v");

  return CommandLine().parse(argc, argv);
}
