//
// Created by Spencer Michaels on 8/13/18.
//

#include "Domain.hpp"
#include "XenHandle.hpp"

using xd::xen::Domain;
using xd::xen::XenHandle;

Domain::Domain(XenHandle& xen, Domain::DomID domid)
    : _xen(xen), _domid(domid)
{
  info(); // Make sure we're connected
}

std::string xd::xen::Domain::name() {
  static constexpr size_t PATH_SIZE = 128;

  char path[PATH_SIZE];

  snprintf((char *)&path, PATH_SIZE, "/local/domain/%u/name", _domid);
  char *name = xs_read(_xen._xenstore, XBT_NULL, (char*)&path, NULL);

  if (!name)
    throw std::runtime_error("Failed to get name!");
}

Domain::DomInfo Domain::info() {
  xc_dominfo_t dominfo;
  xc_domain_getinfo(_xen._xenctrl, _domid, 1, &dominfo);

  if (dominfo.domid != _domid)
    throw std::runtime_error("Failed to get dominfo!");
}

