//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_COMMON_HPP
#define XENDBG_COMMON_HPP

#include <cstdint>
#include <memory>

#include "BridgeHeaders/XenCtrl.h"

namespace xd::xen {
  using Address = void*;
  using DomID = uint32_t;
  using DomInfo = xc_dominfo_t;
  using MappedMemory = std::shared_ptr<char>;
  using VCPU_ID = uint32_t;
  using WordSize = unsigned int;
}

#endif //XENDBG_COMMON_HPP
