//
// Created by Spencer Michaels on 8/13/18.
//

#include <Xen/XenCtrl.hpp>
#include <Xen/XenException.hpp>

using xd::xen::DomInfo ;
using xd::xen::XenCtrl;
using xd::xen::XenException;

xd::xen::XenCtrl::XenCtrl()
  : _xenctrl(xc_interface_open(nullptr, nullptr, 0), &xc_interface_close),
    xencall(_xenctrl)
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

DomInfo XenCtrl::get_domain_info(DomID domid) const {
  xc_dominfo_t dominfo;
  int ret = xc_domain_getinfo(_xenctrl.get(), domid, 1, &dominfo);

  // TODO: Why do these get out of sync?! Can I ignore it?
  if (ret != 1) // || dominfo.domid != domid)
    throw XenException("Failed to get domain info!", errno);

  return dominfo;
}
