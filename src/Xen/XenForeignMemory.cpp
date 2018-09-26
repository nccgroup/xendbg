//
// Created by Spencer Michaels on 8/13/18.
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
    : _xen_foreign_memory(xenforeignmemory_open(NULL, 0), xenforeignmemory_close)
{
  if (!_xen_foreign_memory)
    throw XenException("Failed to open Xen foreign memory handle!", errno);
}
