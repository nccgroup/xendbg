//
// Created by Spencer Michaels on 8/17/18.
//

#ifndef XENDBG_PRIVCMD_HPP
#define XENDBG_PRIVCMD_HPP

#include <cstring>
#include <cstddef>
#include <functional>
#include <optional>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <type_traits>
#include <utility>

#include <errno.h>

#include "Common.hpp"
#include "XenException.hpp"

#include "BridgeHeaders/domctl.h"
#include "BridgeHeaders/privcmd.h"

namespace xd::xen {

  class Domain;

  class PrivCmd {
  private:
    static xen_domctl _dummy_domctl;

  public:
    using DomctlUnion = decltype(PrivCmd::_dummy_domctl.u);
    using InitFn = std::function<void(DomctlUnion&)>;
    using CleanupFn = std::function<void()>;

    PrivCmd();
    ~PrivCmd();

    DomctlUnion hypercall_domctl(const Domain &domain, uint32_t command, InitFn init = {}, CleanupFn cleanup = {}) const;

  private:
    int _privcmd_fd;
  };

}

#endif //XENDBG_PRIVCMD_HPP
