//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGERREPL_HPP
#define XENDBG_DEBUGGERREPL_HPP

#include <stdexcept>
#include <string>

#include "Debugger.hpp"
#include "../Parser/Expression/Expression.hpp"
#include "../REPL/REPL.hpp"

namespace xd::dbg {

  class NoGuestAttachedException : public std::exception {
  };

  class InvalidInputException : public std::runtime_error {
  public:
    InvalidInputException(const std::string &what)
      : std::runtime_error(what.c_str()) {};
  };

  class DebuggerREPL {
  public:
    DebuggerREPL();
    DebuggerREPL(const DebuggerREPL &other) = delete;
    DebuggerREPL& operator=(const DebuggerREPL &other) = delete;

    void run();

  private:
    xen::Domain& get_domain_or_fail();
    void setup_repl();
    static void print_domain_info(const xen::Domain& domain);
    static void print_registers(const xen::Registers& regs);
    static void print_xen_info(const xen::XenHandle& xen);
    uint64_t evaluate_expression(const parser::expr::Expression& expr, bool allow_write);

  private:
    Debugger _debugger;
    repl::REPL _repl;
  };

}

#endif //XENDBG_DEBUGGERREPL_HPP
