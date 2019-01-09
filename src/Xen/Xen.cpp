//
// Copyright (C) 2018-2019 Spencer Michaels
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include <Xen/Xen.hpp>

#include <unordered_set>

using xd::xen::DomID;
using xd::xen::DomainAny;
using xd::xen::DomainHVM;
using xd::xen::DomainPV;
using xd::xen::Xen;

std::optional<DomainAny> Xen::get_domain_from_name(const std::string &name) {
  auto domains = get_domains();
  for (const auto &domain : domains) {
    if (Xen::get_name_any(domain) == name) {
      return domain;
    }
  }
  return std::nullopt;
}

std::optional<DomainAny> Xen::get_domain_from_domid(DomID domid) {
  auto domains = get_domains();
  for (const auto &domain : domains) {
    if (Xen::get_domid_any(domain) == domid) {
      return domain;
    }
  }
  return std::nullopt;
}

DomID Xen::get_domid_any(const xd::xen::DomainAny &domain_any) {
  return std::visit(xd::util::overloaded {
    [](const auto &domain) {
      return domain.get_domid();
    }
  }, domain_any);
}

std::string Xen::get_name_any(const xd::xen::DomainAny &domain_any) {
  return std::visit(xd::util::overloaded {
      [](const auto &domain) {
        return domain.get_name();
      }
  }, domain_any);
}

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

  /* We have to account for the fact that Xenstore sometimes contains entries
     for dead domains that don't actually exist anymore. These will have the
     same name but a lower domid, and can be safely ignored.
   */
  for (const auto domid_str : domid_strs) {
    const auto domid = std::stoul(domid_str);
    try {
      auto domain = init_domain(domid);

      auto it = std::find_if(domains.begin(), domains.end(),
        [&](auto &d) {
          return get_domid_any(d) < domid;
        });

      if (it != domains.end())
        domains.erase(it);

      domains.push_back(std::move(domain));
    } catch (xen::XenException &e) {
      // Sometimes Xenstore yields dead domains, just skip them
      continue;
    }
  }

  return domains;
}
