//
// Created by Spencer Michaels on 9/26/18.
//

#include <Xen/DomainAny.hpp>

using xd::xen::Domain;
using xd::xen::DomainAny;
using xd::xen::DomID;
using xd::xen::get_domain_info;

std::shared_ptr<Domain> xd::xen::init_domain(DomID domid, XenCall &privcmd, XenEventChannel &xenevtchn,
    XenCtrl &xenctrl, XenForeignMemory &xenforeignmemory, XenStore &xenstore)
{
  auto dominfo = get_domain_info(xenctrl, domid);
  if (dominfo.hvm)
    return std::make_shared<DomainHVM>(domid, privcmd, xenevtchn, xenctrl, xenforeignmemory, xenstore);
  else
    return std::make_shared<DomainPV>(domid, privcmd, xenevtchn, xenctrl, xenforeignmemory, xenstore);
}


std::vector<std::shared_ptr<Domain>> xd::xen::get_domains(XenCall &privcmd, XenEventChannel &xenevtchn,
    XenCtrl &xenctrl, XenForeignMemory &xenforeignmemory, XenStore &xenstore)
{
  auto domid_strs = xenstore.read_directory("/local/domain");

  // Exclude domain 0
  domid_strs.erase(std::remove(domid_strs.begin(), domid_strs.end(), "0"));

  std::vector<std::shared_ptr<Domain>> domains;
  domains.reserve(domid_strs.size());
  std::transform(domid_strs.begin(), domid_strs.end(), std::back_inserter(domains),
    [&](const auto& domid_str) {
      const auto domid = std::stoul(domid_str);
      return init_domain(domid, privcmd, xenevtchn, xenctrl, xenforeignmemory, xenstore);
    });
  return domains;
}

