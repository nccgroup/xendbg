//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGER_HPP
#define XENDBG_DEBUGGER_HPP

#include <optional>
#include <memory>
#include <unordered_map>
#include <vector>

#include "Xen/Domain.hpp"

namespace xd {

  class Debugger {
  private:
    using VarMap = std::unordered_map<std::string, uint64_t>;

    // TODO: Move these elsewhere
    struct Symbol {
      uint64_t address;
    };

  public:
    xen::Domain& attach(xen::DomID domid);
    void detach();

    void load_symbols_from_file(const std::string &name);

    xen::XenHandle &get_xen_handle() { return _xen; };
    std::optional<xen::Domain>& get_current_domain() { return _domain; };
    std::vector<xen::Domain> get_guest_domains();
    const Symbol &lookup_symbol(const std::string &name);

    const VarMap& get_vars() { return _variables; };
    uint64_t get_var(const std::string &name);
    void set_var(const std::string &name, uint64_t value);
    void delete_var(const std::string &name);

  private:
    std::unordered_map<std::string, Symbol> _symbols;

    size_t _current_vcpu;
    xen::XenHandle _xen;
    std::optional<xen::Domain> _domain;
    VarMap _variables;
    // TODO: breakpoints
  };

}


#endif //XENDBG_DEBUGGER_HPP
