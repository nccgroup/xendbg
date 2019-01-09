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

//
// Created by Spencer Michaels on 8/17/18.
//

#include <fcntl.h>
#include <sys/errno.h>
#include <unistd.h>

#include <Xen/BridgeHeaders/xenctrl.h>

#include <Xen/Domain.hpp>
#include <Xen/XenCall.hpp>

using xd::xen::XenCall;
using xd::xen::XenException;


XenCall::XenCall(std::shared_ptr<xc_interface> xenctrl)
  : _xencall(xencall_open(nullptr, 0), &xencall_close),
    _xenctrl(std::move(xenctrl))
{
  if (!_xencall)
    throw XenException("Failed to open xencall interface!", errno);
}

XenCall::DomctlUnion XenCall::do_domctl(const Domain &domain,
                                        uint32_t command, InitFn init, CleanupFn cleanup) const
{
  DECLARE_HYPERCALL_BUFFER(xen_domctl, domctl);

  domctl = (xen_domctl*)(xc_hypercall_buffer_alloc(_xenctrl.get(), domctl, sizeof(*domctl)));
  if (!domctl)
    throw std::runtime_error("failed to alloc hypercall buffer");

  domctl->domain = domain.get_domid();
  domctl->interface_version = XEN_DOMCTL_INTERFACE_VERSION;
  domctl->cmd = command;

  memset(&domctl->u, 0, sizeof(domctl->u));
  if (init)
    init(domctl->u);

  const auto err = xencall1(_xencall.get(), __HYPERVISOR_domctl, HYPERCALL_BUFFER_AS_ARG(domctl));
  auto u = domctl->u;

  xc_hypercall_buffer_free(_xenctrl.get(), domctl);

  if (cleanup)
    cleanup();

  if (err)
    throw XenException("Hypercall failed", -err);

  return u;
}
