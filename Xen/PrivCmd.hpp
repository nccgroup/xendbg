//
// Created by Spencer Michaels on 8/17/18.
//

#ifndef XENDBG_PRIVCMD_H
#define XENDBG_PRIVCMD_H

#include <cstring>
#include <cstddef>
#include <functional>
#include <optional>
#include <sys/mman.h>
#include <type_traits>
#include <utility>

#include "BridgeHeaders/domctl.h"

namespace xd::xen {

  class Domain;

  class PrivCmd {
  private:
    static xen_domctl __dummy_domctl;

    PrivCmd();
    ~PrivCmd();

    template<InitFn_t, CleanupFn_t>
    void hypercall_domctl(Domain& domain, uint32_t command, InitFn_t init_domctl = {}, CleanupFn_t cleanup = {}) {
      xen_domctl domctl;
      domctl.domain = domain.get_domid();
      domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
      domctl.cmd = command;

      memset(&domctl.u, 0, sizeof(domctl.u));
      init_domctl(&domctl.u);

      privcmd_hypercall hypercall;
      hypercall.op = __HYPERVISOR_domctl;
      hypercall.arg[0] = (unsigned long)&domctl;

      int err = ioctl(_privcmd_fd, IOCTL_PRIVCMD_HYPERCALL, &hypercall);
      cleanup();

      if (err)
        throw XenException("Hypercall failed: " + std::string(std::strerror(errno)));
    }

  private:
    int _privcmd_fd;
  };

}

#endif //XENDBG_PRIVCMD_H
