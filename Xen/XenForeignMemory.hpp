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
    xen_pfn_t pfn_to_mfn_pv(xen_pfn_t pfn, xen_pfn_t *p2m_table, WordSize word_size) const;

  private:
    std::shared_ptr<xenforeignmemory_handle> _xen_foreign_memory;
  };

}

#endif //XENDBG_FOREIGNMEMORY_HPP
