//
// Created by Spencer Michaels on 8/13/18.
//

#include <xenstore.h>

#include "Domain.hpp"
#include "XenHandle.hpp"

using xd::xen::Domain;
using xd::xen::DomInfo;
using xd::xen::XenHandle;

Domain::Domain(XenHandle& xen, DomID domid)
    : _xen(xen), _domid(domid)
{
  info(); // Make sure we can connect to Xen
}

std::string xd::xen::Domain::name() {
  const auto path = "/local/domain/" + std::to_string(_domid) + "/name";
  return _xen.xenstore().read(path);
}

DomInfo Domain::info() {
  return _xen.xenctrl().get_domain_info(*this);
}

void xd::xen::Domain::set_debugging(bool enabled) {
}

void xd::xen::Domain::set_single_step(bool enabled) {

}

void xd::xen::Domain::pause() {

}

void xd::xen::Domain::unpause() {

}
