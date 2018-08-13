//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_DOMAIN_HPP
#define XENDBG_DOMAIN_HPP

#include <cstdint>
#include <string>

#include <xenctrl.h>

namespace xd::xen {

  class XenHandle;

  class Domain {
  public:
    using DomID = uint32_t ;
    using DomInfo = xc_dominfo_t;

  public:
    explicit Domain(XenHandle& xen, DomID domid);

    std::string name();
    DomInfo info();

  private:
    const DomID _domid;
    XenHandle& _xen;
  };

}

#endif //XENDBG_DOMAIN_HPP

