//
// Copyright (C) 2018-2019 NCC Group
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
