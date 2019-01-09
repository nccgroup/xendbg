//
// Created by Spencer Michaels on 8/28/18.
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
