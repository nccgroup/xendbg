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

#ifndef XENDBG_DEBUGGERREPL_HPP
#define XENDBG_DEBUGGERREPL_HPP

#include <stdexcept>
#include <string>

#include <capstone/capstone.h>
#include <uvw.hpp>

#include "DebuggerWrapper.hpp"
#include "REPL.hpp"

namespace xd::dbg {

  class NotSupportedException : public std::runtime_error {
  public:
    explicit NotSupportedException(const std::string &what)
      : std::runtime_error(what.c_str()) {};
  };

  class InvalidInputException : public std::runtime_error {
  public:
    explicit InvalidInputException(const std::string &what)
      : std::runtime_error(what.c_str()) {};
  };

  class NoSuchDomainException : public std::runtime_error {
  public:
    explicit NoSuchDomainException(const std::string &what)
      : std::runtime_error(what.c_str()) {};
  };

  class DebuggerREPL {
  public:
    DebuggerREPL(bool non_stop_mode);
    DebuggerREPL(const DebuggerREPL &other) = delete;
    DebuggerREPL& operator=(const DebuggerREPL &other) = delete;

    void run();

  private:
    void setup_repl();

    static void print_domain_info(const xen::Domain& domain);
    static void print_registers(const reg::RegistersX86Any& regs);
    static void print_xen_info(const xen::Xen& xen);
    void examine(uint64_t address, size_t word_size, size_t num_words);
    void disassemble(uint64_t address, size_t length, size_t max_instrs = 0);
    void stop();

  private:
    repl::REPL _repl;
    std::shared_ptr<uvw::Loop> _loop;
    std::shared_ptr<uvw::SignalHandle> _signal;
    repl::DebuggerWrapper _dwrap;
    size_t _vcpu_id, _max_vcpu_id;
    csh _capstone;
  };

}

#endif //XENDBG_DEBUGGERREPL_HPP
