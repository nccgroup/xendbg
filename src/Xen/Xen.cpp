#include <Xen/Xen.hpp>

using xd::xen::DomID;
using xd::xen::DomainAny;
using xd::xen::DomainHVM;
using xd::xen::DomainPV;
using xd::xen::Xen;

DomainAny Xen::init_domain(DomID domid) {
  auto dominfo = _xenctrl.get_domain_info(domid);
  if (dominfo.hvm)
    return DomainHVM(domid, shared_from_this());
  else
    return DomainPV(domid, shared_from_this());
}

std::vector<DomainAny> Xen::get_domains() {
}
