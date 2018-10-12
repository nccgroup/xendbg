//
// Created by Spencer Michaels on 8/17/18.
//

#include <fcntl.h>
#include <sys/errno.h>
#include <unistd.h>

#include <Xen/Domain.hpp>
#include <Xen/PrivCmd.hpp>

using xd::xen::PrivCmd;
using xd::xen::XenException;

PrivCmd::PrivCmd()
  : _privcmd_fd(open("/dev/xen/privcmd", O_RDWR))
{
  if (_privcmd_fd < 0)
    throw XenException("Failed to open privcmd interface!", errno);

  int flags = fcntl(_privcmd_fd, F_GETFD);
  if (flags < 0)
    throw XenException("Failed to get file handle flags!", errno);

  if (fcntl(_privcmd_fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    throw XenException("Failed to set file handle flags!", errno);
}

PrivCmd::~PrivCmd() {
  close(_privcmd_fd);
}

PrivCmd::DomctlUnion PrivCmd::hypercall_domctl(const Domain &domain,
    uint32_t command, InitFn init, CleanupFn cleanup) const
{
  xen_domctl domctl;
  domctl.domain = domain.get_domid();
  domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
  domctl.cmd = command;

  memset(&domctl.u, 0, sizeof(domctl.u));
  if (init)
    init(domctl.u);

  privcmd_hypercall hypercall;
  hypercall.op = __HYPERVISOR_domctl;
  hypercall.arg[0] = (unsigned long)&domctl;

  int err = ioctl(_privcmd_fd, IOCTL_PRIVCMD_HYPERCALL, &hypercall);
  if (cleanup)
    cleanup();

  if (err)
    throw XenException("Hypercall failed: " + std::string(std::strerror(errno)));

  return domctl.u;
}
