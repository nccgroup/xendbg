//
// Created by Spencer Michaels on 8/13/18.
//

#include <cstring>

#include "XenHandle.hpp"

using xd::xen::Domain;
using xd::xen::XenHandle;

XenHandle::XenHandle()
  :  _xenctrl(xc_interface_open(NULL, NULL, 0), xc_interface_close),
    _xenstore(xs_open(0), xs_close),
    _foreign_memory(xenforeignmemory_open(NULL, 0), xenforeignmemory_close)
{
  if (!_xenctrl)
    throw std::runtime_error("Failed to open Xenctrl handle!");
  if (!_xenstore)
    throw std::runtime_error("Failed to open Xenstore handle!");
  if (!_foreign_memory)
    throw std::runtime_error("Failed to open Xen foreign memory handle!");
}

XenHandle::Version XenHandle::version() {
  int version = _version(xc_version(_xenctrl, XENVER_version, NULL));
  return Version {
    version >> 16,
    version & ((1 << 16) - 1)
  };
}

Domain::DomID xd::xen::XenHandle::get_domid_from_name(const std::string& name) {
  static constexpr size_t PATH_SIZE = 128;

  unsigned int domains_size;
  char **domains = xs_directory(_xenstore, XBT_NULL, "/local/domain", &domains_size);

  for (int i = 0; i < domains_size; ++i) {
    char *id_str = domains[i];
    char path[PATH_SIZE];

    snprintf((char *)&path, PATH_SIZE, "/local/domain/%s/name", id_str);

    char *name_candidate = (char*)xs_read(_xenstore, XBT_NULL, (char*)&path, NULL);
    if (name_candidate && !strncmp(name, name_candidate, PATH_SIZE)) {
      return (strtol(id_str, NULL, 10);
    }
  }
}

