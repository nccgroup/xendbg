//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <string>

#include <xenctrl.h>

#include "Common.hpp"

namespace xd::xen {

  class XenHandle;

  class Domain {
  public:
    explicit Domain(XenHandle& xen, DomID domid);

    DomID domid() { return _domid; };
    std::string name();
    DomInfo info();

    void set_debugging(bool enabled);
    void set_single_step(bool enabled);
    void pause();
    void unpause();

  private:
    const DomID _domid;
    XenHandle& _xen;
  };

}

#endif //XENDBG_DOMAIN_HPP

