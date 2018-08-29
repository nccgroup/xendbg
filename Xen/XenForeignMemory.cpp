//
// Created by Spencer Michaels on 8/13/18.
//

#include <cstring>

#include "Domain.hpp"
#include "XenForeignMemory.hpp"
#include "XenException.hpp"

// NOTE: This needs to be declared after Domain.hpp, which includes xenctrl.h.
// For some reason, including xenforeignmemory.h before xenctrl.h will fail.
#include "BridgeHeaders/xenforeignmemory.h"

using xd::xen::MappedMemory;
using xd::xen::WordSize;
using xd::xen::XenForeignMemory;
using xd::xen::XenException;

XenForeignMemory::XenForeignMemory()
    : _xen_foreign_memory(xenforeignmemory_open(NULL, 0), xenforeignmemory_close)
{
  if (!_xen_foreign_memory)
    throw XenException("Failed to open Xen foreign memory handle!");
}

MappedMemory XenForeignMemory::map(const Domain &domain, Address address, size_t size, int prot) const {
  if (address < XC_PAGE_SIZE) {
    throw XenException("Addresses below 0x1000 cannot be mapped!");
  }

  auto meminfo = domain.map_meminfo();
  xen_pfn_t base_mfn = pfn_to_mfn_pv((address >> XC_PAGE_SHIFT)-1, meminfo->p2m_table, domain.get_word_size());

  size_t num_pages = (size + XC_PAGE_SIZE - 1) >> XC_PAGE_SHIFT;

  auto pages = (xen_pfn_t*)malloc(num_pages * sizeof(xen_pfn_t));
  auto errors = (int*)malloc(num_pages * sizeof(int));

  if (!pages)
    throw XenException("Failed to allocate PFN table: " + std::string(std::strerror(errno)));
  if (!errors)
    throw XenException("Failed to allocate error table: " + std::string(std::strerror(errno)));

  for (int i = 0; i < num_pages; ++i) {
    pages[i] = base_mfn + 1;
  }

  char *mem_page_base = (char*)xenforeignmemory_map(_xen_foreign_memory.get(), domain.get_domid(), prot, num_pages, pages, errors);
  char *mem = mem_page_base + address % XC_PAGE_SIZE;

  for (int i = 0; i < num_pages; ++i) {
    if (errors[i])
      throw XenException("Failed to map page " + std::to_string(i+1) + " of " + std::to_string(num_pages) + ": " + std::strerror(-errors[i])); // TODO
  }

  auto fmem = _xen_foreign_memory;
  return std::shared_ptr<char>(mem, [fmem, address, num_pages](void *memory) {
    if (memory) {
      xenforeignmemory_unmap(fmem.get(), (void*)address, num_pages);
    }
  });
}

// See xen/tools/libxc/xc_offline_page.c:389
xen_pfn_t XenForeignMemory::pfn_to_mfn_pv(xen_pfn_t pfn, xen_pfn_t *p2m_table, WordSize word_size) const {
  if (word_size == sizeof(uint64_t)) {
    return ((uint64_t*)p2m_table)[pfn];
  } else {
    uint32_t mfn = ((uint32_t*)p2m_table)[pfn];
    return (mfn == ~0U) ? INVALID_MFN : mfn;
  }
}
