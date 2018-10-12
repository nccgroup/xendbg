//
// Created by Spencer Michaels on 9/26/18.
//

#include <Xen/DomainAny.hpp>

using xd::xen::Domain;
using xd::xen::DomainAny;
using xd::xen::DomID;
using xd::xen::get_domain_info;

DomainAny xd::xen::init_domain(DomID domid, PrivCmd &privcmd, XenEventChannel &xenevtchn,
    XenCtrl &xenctrl, XenForeignMemory &xenforeignmemory, XenStore &xenstore)
{
  auto dominfo = get_domain_info(xenctrl, domid);
  if (dominfo.hvm)
    return DomainHVM(domid, privcmd, xenevtchn, xenctrl, xenforeignmemory, xenstore);
  else
    return DomainPV(domid, privcmd, xenevtchn, xenctrl, xenforeignmemory, xenstore);
}


std::vector<DomainAny> xd::xen::get_domains(PrivCmd &privcmd, XenEventChannel &xenevtchn,
    XenCtrl &xenctrl, XenForeignMemory &xenforeignmemory, XenStore &xenstore)
{
  auto domid_strs = xenstore.read_directory("/local/domain");

  // Exclude domain 0
  domid_strs.erase(std::remove(domid_strs.begin(), domid_strs.end(), "0"));

  std::vector<DomainAny> domains;
  domains.reserve(domid_strs.size());
  std::transform(domid_strs.begin(), domid_strs.end(), std::back_inserter(domains),
    [&](const auto& domid_str) {
      const auto domid = std::stoul(domid_str);
      return init_domain(domid, privcmd, xenevtchn, xenctrl, xenforeignmemory, xenstore);
    });
  return domains;
}

DomID xd::xen::get_domid_any(const xd::xen::DomainAny &domain) {
  return std::visit(xd::util::overloaded {
    [](const auto &domain) {
      return domain.get_domid();
    },
  }, domain);
}
