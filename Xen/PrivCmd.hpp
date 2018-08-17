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

  public:
    using DomCtlInitFn = std::function<void(decltype(__dummy_domctl.u)*)>;

    PrivCmd();
    ~PrivCmd();

    void hypercall_domctl(Domain& domain, uint32_t command, DomCtlInitFn init_domctl = {},
        void *arg = nullptr, int size = 0);

  private:
    int _privcmd_fd;
  };

}

#endif //XENDBG_PRIVCMD_H
