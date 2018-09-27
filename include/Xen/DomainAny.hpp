//
// Created by Spencer Michaels on 9/26/18.
//

#ifndef XENDBG_DOMAINANY_HPP
#define XENDBG_DOMAINANY_HPP

#include <variant>

#include "DomainHVM.hpp"
#include "DomainPV.hpp"

namespace xd::xen {

  using DomainAny = std::variant<DomainPV, DomainHVM>;

  static DomainAny init_domain(DomID domid, XenEventChannel &xenevtchn,
      XenCtrl &xenctrl, XenForeignMemory &xenforiegnmemory, XenStore &xenstore);

}

#endif //XENDBG_DOMAINANY_HPP
