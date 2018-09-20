//
// Created by Spencer Michaels on 9/19/18.
//

#include "Domain.hpp"
#include "XenHandle.hpp"

using xd::xen::Domain;
using xd::xen::XenHandle;

std::vector<Domain> XenHandle::get_domains() const {
  const auto domid_strs = get_xenstore().read_directory("/local/domain");

  std::vector<Domain> domains;
  domains.reserve(domid_strs.size());
  std::transform(domid_strs.begin(), domid_strs.end(), std::back_inserter(domains),
    [this](const auto& domid_str) {
      const auto domid = std::stoul(domid_str);
      return Domain(*this, domid);
    });
  return domains;
}
