//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include <cstring>
#include <iostream>

#include <Xen/Domain.hpp>
#include <Xen/XenForeignMemory.hpp>
#include <Xen/XenException.hpp>

using xd::xen::WordSize;
using xd::xen::XenForeignMemory;
using xd::xen::XenException;

XenForeignMemory::XenForeignMemory()
    : _xen_foreign_memory(xenforeignmemory_open(nullptr , 0), xenforeignmemory_close)
{
  if (!_xen_foreign_memory)
    throw XenException("Failed to open Xen foreign memory handle!", errno);
}

void *XenForeignMemory::map_by_mfn_raw(const Domain &domain, Address base_mfn, Address offset, size_t size, int prot) const {
  size_t num_pages = (size + XC_PAGE_SIZE - 1) >> XC_PAGE_SHIFT;

  auto pages = (xen_pfn_t*)malloc(num_pages * sizeof(xen_pfn_t));
  auto errors = (int*)malloc(num_pages * sizeof(int));

  if (!pages)
    throw XenException("Failed to allocate PFN table: ", errno);
  if (!errors)
    throw XenException("Failed to allocate error table: ", errno);

  for (size_t i = 0; i < num_pages; ++i)
    pages[i] = base_mfn + i;

  char *mem_page_base =
      (char*)xenforeignmemory_map(_xen_foreign_memory.get(),
                                  domain.get_domid(), prot, num_pages, pages, errors);

  for (size_t i = 0; i < num_pages; ++i)
    if (errors[i])
      throw XenException("Failed to map page " +
                         std::to_string(i+1) + " of " +
                         std::to_string(num_pages), -errors[i]);

  return (void*)(mem_page_base + offset);
}
