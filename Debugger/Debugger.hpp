//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGER_HPP
#define XENDBG_DEBUGGER_HPP

#include <optional>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "../Xen/Domain.hpp"

namespace xd::dbg {

  class NoGuestAttachedException : public std::exception {
  };

  class NoSuchBreakpointException : public std::exception{
  public:
    NoSuchBreakpointException(const size_t id)
      : _id(id) {};

    size_t get_id() const { return _id; };

  private:
    size_t _id;
  };

  class NoSuchVariableException : public std::runtime_error {
  public:
    NoSuchVariableException(const std::string &name)
      : std::runtime_error(name) {};
  };

  class NoSuchSymbolException : public std::runtime_error {
  public:
    NoSuchSymbolException(const std::string &name)
      : std::runtime_error(name) {};
  };

  class Debugger {
  private:
    struct Symbol {
      uint64_t address;
    };
    struct Breakpoint {
      size_t id;
      uint64_t address;
      uint16_t orig_bytes;
    };


    using BreakpointMap = std::unordered_map<size_t, Breakpoint>;
    using SymbolMap = std::unordered_map<std::string, Symbol>;
    using VarMap = std::unordered_map<std::string, uint64_t>;

  public:
    xen::Domain& attach(xen::DomID domid);
    void detach();

    void load_symbols_from_file(const std::string &name);

    size_t create_breakpoint(xen::Address address);
    void delete_breakpoint(size_t id);
    Breakpoint continue_until_breakpoint();

    xen::XenHandle &get_xen_handle() { return _xen; };
    std::optional<xen::Domain>& get_current_domain() { return _domain; };
    std::vector<xen::Domain> get_guest_domains();
    const Symbol &lookup_symbol(const std::string &name);

    const BreakpointMap get_breakpoints() { return _breakpoints; }
    const SymbolMap& get_symbols() { return _symbols; };
    const VarMap& get_vars() { return _variables; };

    uint64_t get_var(const std::string &name);
    void set_var(const std::string &name, uint64_t value);
    void delete_var(const std::string &name);

  private:
    std::optional<Breakpoint> check_breakpoint_hit();

  private:
    size_t _current_vcpu;
    xen::XenHandle _xen;
    std::optional<xen::Domain> _domain;

    size_t _next_breakpoint_id;
    SymbolMap _symbols;
    BreakpointMap _breakpoints;
    VarMap _variables;
  };

}


#endif //XENDBG_DEBUGGER_HPP
