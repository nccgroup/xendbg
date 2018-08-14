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
    int word_size();

    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0);
    void set_single_step(bool enabled, VCPU_ID vcpu_id = 0);
    void pause();
    void unpause();

  private:
    XenHandle& _xen;

    const DomID _domid;
  };

}

#endif //XENDBG_DOMAIN_HPP

