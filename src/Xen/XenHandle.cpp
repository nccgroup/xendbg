//
// Created by Spencer Michaels on 9/19/18.
//

#include "Domain.hpp"
#include "XenHandle.hpp"

using xd::xen::Domain;
using xd::xen::XenHandlePtr;

std::vector<Domain> xd::xen::get_domains(XenHandlePtr xen) {
  auto domid_strs = xen->get_xenstore().read_directory("/local/domain");

  // Exclude domain 0
  domid_strs.erase(std::remove(domid_strs.begin(), domid_strs.end(), "0"));

  std::vector<Domain> domains;
  domains.reserve(domid_strs.size());
  std::transform(domid_strs.begin(), domid_strs.end(), std::back_inserter(domains),
    [&](const auto& domid_str) {
      const auto domid = std::stoul(domid_str);
      return Domain(xen, domid);
    });
  return domains;
}
