//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGER_HPP
#define XENDBG_DEBUGGER_HPP

#include <optional>
#include <memory>
#include <vector>

#include "Xen/Domain.hpp"

namespace xd {

  class Debugger {
  public:
    xen::Domain& attach(xen::DomID domid);
    void detach();

    xen::XenHandle &get_xen_handle() { return _xen; };
    std::optional<xen::Domain>& get_current_domain() { return _domain; };
    std::vector<xen::Domain> get_all_domains();

  private:
    xen::XenHandle _xen;
    std::optional<xen::Domain> _domain;
    // TODO: variables, including special registers
    // TODO: breakpoints
  };

}


#endif //XENDBG_DEBUGGER_HPP
