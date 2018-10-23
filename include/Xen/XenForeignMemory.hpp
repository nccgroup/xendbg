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

    xenforeignmemory_handle *get() { return _xen_foreign_memory.get(); };

    template <typename Memory_t, typename Domain_t>
    MappedMemory<Memory_t> map_by_mfn(const Domain_t &domain, Address base_mfn, Address offset, size_t size, int prot) const {
      auto fmem = _xen_foreign_memory;
      auto mem = map_by_mfn_raw(domain, base_mfn, offset, size, prot);
      auto num_pages = size / XC_PAGE_SIZE;

      return std::shared_ptr<Memory_t>((Memory_t*)mem, [fmem, mem, num_pages](void *memory) {
        if (memory)
          xenforeignmemory_unmap(fmem.get(), mem, num_pages);
      });
    }

  private:
    std::shared_ptr<xenforeignmemory_handle> _xen_foreign_memory;

    void *map_by_mfn_raw(const Domain &domain, Address base_mfn, Address offset, size_t size, int prot) const;
  };

}

#endif //XENDBG_FOREIGNMEMORY_HPP
