//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGERREPL_HPP
#define XENDBG_DEBUGGERREPL_HPP

#include <stdexcept>
#include <string>

#include "DebuggerWrapper.hpp"
#include "REPL.hpp"

namespace xd::dbg {

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

  private:
    repl::REPL _repl;
    repl::DebuggerWrapper _dwrap;
  };

}

#endif //XENDBG_DEBUGGERREPL_HPP
