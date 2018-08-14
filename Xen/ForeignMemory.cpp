//
// Created by Spencer Michaels on 8/13/18.
//

#include <xenforeignmemory.h>
#include "ForeignMemory.hpp"

#include "XenException.hpp"

using xd::xen::ForeignMemory;
using xd::xen::XenException;

ForeignMemory::ForeignMemory()
    : _foreign_memory(xenforeignmemory_open(NULL, 0), xenforeignmemory_close)
{
  if (!_foreign_memory)
  throw XenException("Failed to open Xen foreign memory handle!");
}
