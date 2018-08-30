//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGERREPL_HPP
#define XENDBG_DEBUGGERREPL_HPP

#include <string>

#include "Debugger.hpp"
#include "Parser/Expression/Expression.hpp"
#include "REPL/REPL.hpp"

namespace xd {

  class DebuggerREPL {
  public:
    DebuggerREPL();
    DebuggerREPL(const DebuggerREPL &other) = delete;
    DebuggerREPL& operator=(const DebuggerREPL &other) = delete;

    void run();

  private:
    xen::Domain& get_domain_or_fail();
    void setup_repl();
    void print_domain_info(const xen::Domain& domain);
    void print_registers(const xen::Registers& regs);
    void print_xen_info(const xen::XenHandle& xen);

    parser::expr::Expression parse_expression(const std::string &s);
    void evaluate_expression(parser::expr::Expression expr);

  private:
    Debugger _debugger;
    repl::REPL _repl;
  };

}

#endif //XENDBG_DEBUGGERREPL_HPP
