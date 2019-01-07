//
// Created by smichaels on 1/7/19.
//

#ifndef XENDBG_DEBUGGERWRAPPER_HPP
#define XENDBG_DEBUGGERWRAPPER_HPP

#include <memory>

#include <uvw.hpp>

#include <Debugger/Debugger.hpp>
#include <Xen/Xen.hpp>

#include "Parser/Expression/Expression.hpp"

namespace xd::repl {

  class NoSuchSymbolException : public std::runtime_error {
  public:
    explicit NoSuchSymbolException(const std::string &name)
      : std::runtime_error(name.c_str())
    {};
  };

  class NoSuchVariableException : public std::runtime_error {
  public:
    explicit NoSuchVariableException(const std::string &name)
        : std::runtime_error(name.c_str())
    {};
  };

  class InvalidExpressionException : public std::runtime_error {
  public:
    explicit InvalidExpressionException(const std::string &what)
        : std::runtime_error(what.c_str()) {};
  };

  class NoGuestAttachedException : public std::exception {
  };

  class DebuggerWrapper {
  public:
    struct Symbol {
      uint64_t address;
    };

    using SymbolMap = std::unordered_map<std::string, Symbol>;

  public:
    explicit DebuggerWrapper(bool non_stop_mode);
    ~DebuggerWrapper() = default;

    const xd::xen::Domain &get_domain_or_fail() {
      return get_debugger_or_fail()->get_domain();
    }

    std::shared_ptr<xd::dbg::Debugger> get_debugger_or_fail() {
      assert_attached();
      return _debugger;
    }

    std::shared_ptr<xd::dbg::Debugger> get_debugger() {
      return _debugger;
    }

    void attach(xd::xen::DomainAny domain_any);
    void detach();

    uint64_t get_var(const std::string &name);
    void set_var(const std::string &name, uint64_t value);
    void delete_var(const std::string &name);

    uint64_t evaluate_expression(const parser::expr::Expression& expr);
    void evaluate_set_expression(const parser::expr::Expression& expr, size_t word_size);
    xd::dbg::MaskedMemory examine(uint64_t address, size_t word_size, size_t num_words);

    const Symbol &lookup_symbol(const std::string &name);
    const SymbolMap &get_symbols() { return _symbols; };

    const xen::Xen &get_xen_handle() { return *_xen; };

  private:
    void assert_attached();
    void load_symbols_from_file(const std::string &name);

  private:

    using VarMap = std::unordered_map<std::string, uint64_t>;

    bool _non_stop_mode;

    std::shared_ptr<xen::Xen> _xen;
    std::shared_ptr<uvw::Loop> _loop;

    std::shared_ptr<xd::dbg::Debugger> _debugger;
    VarMap _variables;
    SymbolMap _symbols;

    xen::VCPU_ID _vcpu_id;
  };

}


#endif //XENDBG_DEBUGGERWRAPPER_HPP
