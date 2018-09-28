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

  DomainAny init_domain(DomID domid, XenEventChannel &xenevtchn,
      XenCtrl &xenctrl, XenForeignMemory &xenforeignmemory, XenStore &xenstore);

  std::vector<DomainAny> get_domains(XenEventChannel &xenevtchn,
      XenCtrl &xenctrl, XenForeignMemory &xenforeignmemory, XenStore &xenstore);

  xd::xen::DomID get_domid_any(const xd::xen::DomainAny &domain);

}

#endif //XENDBG_DOMAINANY_HPP
