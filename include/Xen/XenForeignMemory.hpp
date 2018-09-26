//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_FOREIGNMEMORY_HPP
#define XENDBG_FOREIGNMEMORY_HPP

#include <iostream>
#include <errno.h>
#include <memory>

// NOTE: This order is necessary. For some reason, including
// xenforeignmemory.h before xenctrl.h will fail.
#include "BridgeHeaders/xenctrl.h"
#include "BridgeHeaders/xenforeignmemory.h"

#include "Common.hpp"
#include "XenException.hpp"

struct xenforeignmemory_handle;

namespace xd::xen {

  class Domain;

  class XenForeignMemory {
  public:
    template <typename Memory_t>
    using MappedMemory = std::shared_ptr<Memory_t>;

    XenForeignMemory();

    template <typename Memory_t, typename Domain_t>
    MappedMemory<Memory_t> map(const Domain_t &domain, Address address, size_t size, int prot) const {
      xen_pfn_t base_mfn = domain.pfn_to_mfn_pv(address >> XC_PAGE_SHIFT);
      return map_by_mfn<Memory_t, Domain_t>(domain, base_mfn, address % XC_PAGE_SIZE, size, prot);
    }

    template <typename Memory_t, typename Domain_t>
    MappedMemory<Memory_t> map_by_mfn(const Domain_t &domain, Address base_mfn, Address offset, size_t size, int prot) const {
      size_t num_pages = (size + XC_PAGE_SIZE - 1) >> XC_PAGE_SHIFT;

      auto pages = (xen_pfn_t*)malloc(num_pages * sizeof(xen_pfn_t));
      auto errors = (int*)malloc(num_pages * sizeof(int));

      if (!pages)
        throw XenException("Failed to allocate PFN table: ", errno);
      if (!errors)
        throw XenException("Failed to allocate error table: ", errno);

      for (size_t i = 0; i < num_pages; ++i) {
        pages[i] = base_mfn + i;
      }

      char *mem_page_base = (char*)xenforeignmemory_map(_xen_foreign_memory.get(),
          domain.get_domid(), prot, num_pages, pages, errors);
      Memory_t *mem = (Memory_t*)(mem_page_base + offset);

      for (size_t i = 0; i < num_pages; ++i) {
        if (errors[i])
          throw XenException("Failed to map page " + std::to_string(i+1) + " of " +
              std::to_string(num_pages), -errors[i]);
      }

      auto fmem = _xen_foreign_memory;
      return std::shared_ptr<Memory_t>(mem, [fmem, mem_page_base, num_pages](void *memory) {
        if (memory) {
          xenforeignmemory_unmap(fmem.get(), (void*)mem_page_base, num_pages);
        }
      });
    }

  private:
    std::shared_ptr<xenforeignmemory_handle> _xen_foreign_memory;

  };

}

#endif //XENDBG_FOREIGNMEMORY_HPP
