//
// Created by Spencer Michaels on 8/17/18.
//

#ifndef XENDBG_DOMCTL_H
#define XENDBG_DOMCTL_H

#include <cstring>
#include <cstddef>
#include <functional>
#include <optional>
#include <sys/mman.h>
#include <type_traits>
#include <utility>

#include "Domain.hpp"

#include "BridgeHeaders/domctl.h"

namespace xd::xen {

  class DomCtl {
  private:
    static xen_domctl __dummy_domctl;
    using DomCtlInitFn = std::function<void(decltype(__dummy_domctl.u)*)>;

  public:
    DomCtl();
    ~DomCtl();

    void do_domctl(Domain& domain, uint32_t command, DomCtlInitFn init_domctl = {},
        void *arg = nullptr, int size = 0)
    {
      xen_domctl domctl;
      domctl.domain = domain.get_domid();
      domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
      domctl.cmd = command;

      memset(&domctl.u, 0, sizeof(domctl.u));
      init_domctl(&domctl.u);
      printf("%d\n", domctl.u.gdbsx_guest_memio.gva);

      do_hypercall(domctl, arg, size);
    }

  private:
    int _privcmd_fd;

    void do_hypercall(xen_domctl& domctl, void *arg, int size);
  };

}

#endif //XENDBG_DOMCTL_H
