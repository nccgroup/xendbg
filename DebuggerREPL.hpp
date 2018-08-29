//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGERREPL_HPP
#define XENDBG_DEBUGGERREPL_HPP

#include "Debugger.hpp"
#include "REPL/REPL.hpp"

namespace xd {

  class DebuggerREPL {
  public:
    DebuggerREPL();
    DebuggerREPL(const DebuggerREPL &other) = delete;
    DebuggerREPL& operator=(const DebuggerREPL &other) = delete;

    void run();

  private:
    void setup_repl();

  private:
    Debugger _debugger;
    repl::REPL _repl;
  };

}

#endif //XENDBG_DEBUGGERREPL_HPP
