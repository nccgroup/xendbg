//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_FOREIGNMEMORY_HPP
#define XENDBG_FOREIGNMEMORY_HPP

#include <memory>

#include "BridgeHeaders/xenctrl.h"

#include "Common.hpp"

struct xenforeignmemory_handle;

namespace xd::xen {

  class Domain;
  class XenForeignMemory;

  class XenForeignMemory {
  public:
    XenForeignMemory();

    MappedMemory map(const Domain& domain, Address address, size_t size, int prot) const;

  private:
    std::shared_ptr<xenforeignmemory_handle> _xen_foreign_memory;

  private:
    static xen_pfn_t pfn_to_mfn_pv(const Domain &domain, xen_pfn_t pfn);
  };

}

#endif //XENDBG_FOREIGNMEMORY_HPP
