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

XenCall::XenCall()
  : _xencall(xencall_open(nullptr, 0), &xencall_close)
{
  if (!_xencall)
    throw XenException("Failed to open xencall interface!", errno);
}

XenCall::DomctlUnion XenCall::do_domctl(const Domain &domain,
                                        uint32_t command, InitFn init, CleanupFn cleanup) const
{
  xen_domctl domctl;
  domctl.domain = domain.get_domid();
  domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
  domctl.cmd = command;

  memset(&domctl.u, 0, sizeof(domctl.u));
  if (init)
    init(domctl.u);

  const auto err = xencall1(_xencall.get(), __HYPERVISOR_domctl, (uint64_t)&domctl);

  if (cleanup)
    cleanup();

  if (err)
    throw XenException("Hypercall failed", -err);

  return domctl.u;
}
