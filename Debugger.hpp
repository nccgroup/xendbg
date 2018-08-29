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
  public:
    xen::Domain& attach(xen::DomID domid);
    void detach();

    xen::XenHandle &get_xen_handle() { return _xen; };
    std::optional<xen::Domain>& get_current_domain() { return _domain; };
    std::vector<xen::Domain> get_guest_domains();

    uint64_t get_var(const std::string &name);
    void set_var(const std::string &name, uint64_t value);

  private:
    size_t _current_cpu;
    xen::XenHandle _xen;
    std::optional<xen::Domain> _domain;
    std::unordered_map<std::string, uint64_t> _variables;
    // TODO: breakpoints
  };

}


#endif //XENDBG_DEBUGGER_HPP
