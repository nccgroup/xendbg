//
// Created by Spencer Michaels on 8/28/18.
//

#include <stdexcept>

#include "Debugger.hpp"

using xd::Debugger;
using xd::xen::Domain;
using xd::xen::DomID;
using xd::xen::XenHandle;

Domain& Debugger::attach(DomID domid) {
  _domain.emplace(_xen, domid);
  return _domain.value();
}

void Debugger::detach() {
  _domain.reset();
}

std::vector<Domain> Debugger::get_all_domains() {
  const auto domids = _xen.get_xenstore().get_all_domids();

  std::vector<Domain> domains;
  domains.reserve(domids.size());
  std::transform(domids.begin(), domids.end(), std::back_inserter(domains),
    [](const auto& domid) {
      return Domain(domid);
    });
  return domains;
}
