//
// Created by Spencer Michaels on 8/17/18.
//

#ifndef XENDBG_DOMCTL_H
#define XENDBG_DOMCTL_H

#include <cstddef>

#include "BridgeHeaders/domctl.h"

#include "Domain.hpp"

namespace xd::xen {

  class DomCtl {
  public:
    DomCtl();
    ~DomCtl();

    template <typename InitFn_t>
    void do_domctl(Domain& domain, uint32_t command, InitFn_t init_domctl) {
      xen_domctl domctl;
      domctl.domain = domain.get_domid();
      domctl.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
      domctl.cmd = command;

      memset(&domctl.u, 0, sizeof(domctl.u));
      auto args = init_domctl(domctl.u);

      if (args) {
        auto [arg, size] = args.value();
        do_hypercall(domctl, arg, size);
      } else {
        do_hypercall(domctl);
      }
    }

  private:
    int _privcmd_fd;

    void do_hypercall(xen_domctl& domctl, void *arg = nullptr, int size = 0);
  };

}

#endif //XENDBG_DOMCTL_H
