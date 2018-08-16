//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_COMMON_HPP
#define XENDBG_COMMON_HPP

#include <cstdint>
#include <functional>
#include <memory>

#include "BridgeHeaders/xenctrl.h"
#include "BridgeHeaders/xenguest.h"

namespace xd::xen {
  using Address = uintptr_t;
  using DomID = uint32_t;
  using DomInfo = xc_dominfo_t;
  using MappedMemory = std::shared_ptr<char>;
  using MemInfo = std::unique_ptr<xc_domain_meminfo, std::function<void(xc_domain_meminfo *p)>>;
  using VCPU_ID = uint32_t;
  using WordSize = unsigned int;
}

#endif //XENDBG_COMMON_HPP
