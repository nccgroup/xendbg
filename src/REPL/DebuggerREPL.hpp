//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGERREPL_HPP
#define XENDBG_DEBUGGERREPL_HPP

#include <stdexcept>
#include <string>

#include "../Debugger/Debugger.hpp"
#include "../Parser/Expression/Expression.hpp"
#include "REPL.hpp"

namespace xd::dbg {

  class InvalidInputException : public std::runtime_error {
  public:
    InvalidInputException(const std::string &what)
      : std::runtime_error(what.c_str()) {};
  };

  class NoSuchVariableException : public std::runtime_error {
  public:
    explicit NoSuchVariableException(const std::string &name)
      : std::runtime_error(name) {};
  };

  class DebuggerREPL {
  public:
    DebuggerREPL();
    DebuggerREPL(const DebuggerREPL &other) = delete;
    DebuggerREPL& operator=(const DebuggerREPL &other) = delete;

    void run();

  private:
    using SymbolMap = std::unordered_map<std::string, Symbol>;
    using VarMap = std::unordered_map<std::string, uint64_t>;

    xen::Domain& get_domain_or_fail();
    void setup_repl();
    static void print_domain_info(const xen::Domain& domain);
    static void print_registers(const xen::Registers& regs);
    static void print_xen_info(const xen::XenHandle& xen);
    uint64_t evaluate_expression(const parser::expr::Expression& expr);
    void evaluate_set_expression(const parser::expr::Expression& expr, size_t word_size);
    void examine(uint64_t address, size_t word_size, size_t num_words);

    void load_symbols_from_file(const std::string &name);
    const Symbol &lookup_symbol(const std::string &name);

    uint64_t get_var(const std::string &name);
    void set_var(const std::string &name, uint64_t value);
    void delete_var(const std::string &name);

  private:
    Debugger _debugger;
    repl::REPL _repl;

    VarMap _variables;
    SymbolMap _symbols;
  };

}

#endif //XENDBG_DEBUGGERREPL_HPP
