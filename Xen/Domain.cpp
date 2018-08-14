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
  info(); // Make sure the domain is behaving properly
}

std::string xd::xen::Domain::name() {
  const auto path = "/local/domain/" + std::to_string(_domid) + "/name";
  return _xen.xenstore().read(path);
}

DomInfo Domain::info() {
  return _xen.xenctrl().get_domain_info(*this);
}

int xd::xen::Domain::word_size() {
  return _xen.xenctrl().get_domain_word_size(*this);
}

void xd::xen::Domain::set_debugging(bool enabled, VCPU_ID vcpu_id) {
  _xen.xenctrl().set_domain_debugging(*this, enabled, vcpu_id);
}

void xd::xen::Domain::set_single_step(bool enabled, VCPU_ID vcpu_id) {
  _xen.xenctrl().set_domain_single_step(*this, enabled, vcpu_id);
}

void xd::xen::Domain::pause() {
  _xen.xenctrl().pause_domain(*this);
}

void xd::xen::Domain::unpause() {
  _xen.xenctrl().unpause_domain(*this);
}
