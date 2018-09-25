//
// Created by Spencer Michaels on 8/13/18.
//

#include <cstring>
#include <iostream>

#include "Domain.hpp"
#include "XenForeignMemory.hpp"
#include "XenException.hpp"

using xd::xen::WordSize;
using xd::xen::XenForeignMemory;
using xd::xen::XenException;

XenForeignMemory::XenForeignMemory()
    : _xen_foreign_memory(xenforeignmemory_open(NULL, 0), xenforeignmemory_close)
{
  if (!_xen_foreign_memory)
    throw XenException("Failed to open Xen foreign memory handle!", errno);
}

// See xen/tools/libxc/xc_offline_page.c:389
xen_pfn_t XenForeignMemory::pfn_to_mfn_pv(const Domain &domain, xen_pfn_t pfn) {
  const auto meminfo = domain.map_meminfo();
  const auto word_size = domain.get_word_size();

  if (pfn > meminfo->p2m_size)
    throw XenException("Invalid PFN!");

  if (word_size == sizeof(uint64_t)) {
    return ((uint64_t*)meminfo->p2m_table)[pfn];
  } else {
    uint32_t mfn = ((uint32_t*)meminfo->p2m_table)[pfn];
    return (mfn == ~0U) ? INVALID_MFN : mfn;
  }
}
