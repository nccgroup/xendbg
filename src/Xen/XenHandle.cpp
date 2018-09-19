//
// Created by Spencer Michaels on 9/19/18.
//

#include "Domain.hpp"
#include "XenHandle.hpp"

using xd::xen::Domain;
using xd::xen::XenHandle;

std::vector<Domain> XenHandle::get_domains() const {
  const auto domids = get_xenstore().get_guest_domids();

  std::vector<Domain> domains;
  domains.reserve(domids.size());
  std::transform(domids.begin(), domids.end(), std::back_inserter(domains),
    [this](const auto& domid) {
      return Domain(*this, domid);
    });
  return domains;
}
