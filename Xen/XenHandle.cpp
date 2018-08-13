//
// Created by Spencer Michaels on 8/13/18.
//

#include "XenHandle.hpp"

using xd::xen::XenHandle;

XenHandle::Version::Version(int version)
  : _major(version >> 16),
    _minor(version & ((1 << 16) - 1))
{}

XenHandle::XenHandle()
  :  _xenctrl(xc_interface_open(NULL, NULL, 0), xc_interface_close),
    _xenstore(xs_open(0), xs_close),
    _foreign_memory(xenforeignmemory_open(NULL, 0), xenforeignmemory_close),
    _version(xc_version(_xenctrl.get(), XENVER_version, NULL))
{
  if (!_xenctrl)
    throw std::runtime_error("Failed to open Xenctrl handle!");
  if (!_xenstore)
    throw std::runtime_error("Failed to open Xenstore handle!");
  if (!_foreign_memory)
    throw std::runtime_error("Failed to open Xen foreign memory handle!");
}

