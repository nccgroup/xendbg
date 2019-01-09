//
// Copyright (C) 2018-2019 Spencer Michaels
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
