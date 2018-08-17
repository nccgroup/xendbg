//
// Created by Spencer Michaels on 8/17/18.
//

#include <fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "Domain.hpp"
#include "PrivCmd.hpp"
#include "XenException.hpp"

#include "BridgeHeaders/privcmd.h"

using xd::xen::Domain;
using xd::xen::PrivCmd;
using xd::xen::XenException;

PrivCmd::PrivCmd()
  : _privcmd_fd(open("/dev/xen/privcmd", O_RDWR))
{
  if (_privcmd_fd < 0)
    throw XenException("Failed to open privcmd interface: " + std::string(std::strerror(errno)));

  int flags = fcntl(_privcmd_fd, F_GETFD);
  if (flags < 0)
    throw XenException("Failed to get file handle flags: " + std::string(std::strerror(errno)));

  if (fcntl(_privcmd_fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    throw XenException("Failed to set file handle flags: " + std::string(std::strerror(errno)));
}

PrivCmd::~PrivCmd() {
  close(_privcmd_fd);
}

