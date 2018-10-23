#include <Xen/Xen.hpp>

using xd::xen::DomID;
using xd::xen::DomainAny;
using xd::xen::DomainHVM;
using xd::xen::DomainPV;
using xd::xen::Xen;

DomainAny Xen::init_domain(DomID domid) {
  auto dominfo = xenctrl.get_domain_info(domid);
  if (dominfo.hvm)
    return DomainHVM(domid, shared_from_this());
  else
    return DomainPV(domid, shared_from_this());
}

std::vector<DomainAny> Xen::get_domains() {
  auto domid_strs = xenstore.read_directory("/local/domain");

  // Exclude domain 0
  domid_strs.erase(std::remove(domid_strs.begin(), domid_strs.end(), "0"));

  std::vector<DomainAny> domains;
  domains.reserve(domid_strs.size());
  std::transform(domid_strs.begin(), domid_strs.end(), std::back_inserter(domains),
      [&](const auto& domid_str) {
        const auto domid = std::stoul(domid_str);
        return init_domain(domid);
  });
  return domains;
}
