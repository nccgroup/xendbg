//
// Created by Spencer Michaels on 8/13/18.
//

#include <Xen/XenCtrl.hpp>
#include <Xen/XenException.hpp>

using xd::xen::XenException;

xd::xen::XenCtrl::XenCtrl()
  : _xenctrl(xc_interface_open(nullptr, nullptr, 0), &xc_interface_close)
{
  if (!_xenctrl)
    throw XenException("Failed to open Xenctrl handle!", errno);
}

XenCtrl::XenVersion XenCtrl::get_xen_version() const {
  int version = xc_version(_xenctrl.get(), XENVER_version, NULL);
  return XenVersion {
    version >> 16,
    version & ((1 << 16) - 1)
  };
}

/*
MemoryPermissions XenCtrl::get_domain_memory_permissions(
    const Domain &domain, Address address) const
{
  int err;
  xenmem_access_t permissions;
  xen_pfn_t pfn = address >> XC_PAGE_SHIFT;

  memset(&permissions, 0, sizeof(xenmem_access_t));
  if ((err = xc_get_mem_access(_xenctrl.get(), domain.get_domid(), pfn, &permissions))) {
    throw XenException("Failed to get memory permissions for PFN " +
        std::to_string(pfn) + " of domain " + std::to_string(domain.get_domid()), -err);
  }

  return permissions;
}
*/

