//
// Created by Spencer Michaels on 9/26/18.
//

#include <Xen/DomainAny.hpp>

using xd::xen::DomainAny;
using xd::xen::DomID;
using xd::xen::get_domain_info;

DomainAny xd::xen::init_domain(DomID domid, XenEventChannel &xenevtchn,
    XenCtrl &xenctrl, XenForeignMemory &xenforiegnmemory, XenStore &xenstore)
{
  auto dominfo = get_domain_info(domid);
  if (dominfo.hvm)
    return DomainHVM(domid, xenevtchn, xenctrl, xenforeignmemory, xenstore);
  else
    return DomainPV(domid, xenevtchn, xenctrl, xenforeignmemory, xenstore);
}
