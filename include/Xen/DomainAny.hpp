//
// Created by Spencer Michaels on 9/26/18.
//

#ifndef XENDBG_DOMAINANY_HPP
#define XENDBG_DOMAINANY_HPP

#include <memory>
#include <variant>

#include "DomainHVM.hpp"
#include "DomainPV.hpp"

namespace xd::xen {

  using DomainAny = std::variant<DomainPV, DomainHVM>;

  std::shared_ptr<Domain> init_domain(DomID domid, XenCall &privcmd, XenEventChannel &xenevtchn,
      XenCtrl &xenctrl, XenForeignMemory &xenforeignmemory, XenStore &xenstore);

  std::vector<std::shared_ptr<Domain>> get_domains(XenCall &privcmd, XenEventChannel &xenevtchn,
      XenCtrl &xenctrl, XenForeignMemory &xenforeignmemory, XenStore &xenstore);
}

#endif //XENDBG_DOMAINANY_HPP
