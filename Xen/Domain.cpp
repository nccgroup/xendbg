//
// Created by Spencer Michaels on 8/13/18.
//

#include "Domain.hpp"
#include "Xenctrl.hpp"
#include "XenForeignMemory.hpp"
#include "Xenstore.hpp"

using xd::xen::Domain;
using xd::xen::DomInfo;
using xd::xen::MappedMemory;
using xd::xen::XenCtrl;

Domain::Domain(XenCtrl& xenctrl, XenStore& xenstore, XenForeignMemory& xen_foreign_memory, DomID domid)
    : _xenctrl(xenctrl), _xenstore(xenstore), _xen_foreign_memory(xen_foreign_memory), _domid(domid)
{
  get_info(); // Make sure the domain is behaving properly
}

std::string xd::xen::Domain::get_name() {
  const auto path = "/local/domain/" + std::to_string(_domid) + "/name";
  return _xenstore.read(path);
}

DomInfo Domain::get_info() {
  return _xenctrl.get_domain_info(*this);
}

int xd::xen::Domain::get_word_size() {
  return _xenctrl.get_domain_word_size(*this);
}

MappedMemory Domain::map_memory(Address address, size_t size, int prot) {
  return _xen_foreign_memory.map(*this, address, size, prot);
}

void xd::xen::Domain::set_debugging(bool enabled, VCPU_ID vcpu_id) {
  _xenctrl.set_domain_debugging(*this, enabled, vcpu_id);
}

void xd::xen::Domain::set_single_step(bool enabled, VCPU_ID vcpu_id) {
  _xenctrl.set_domain_single_step(*this, enabled, vcpu_id);
}

void xd::xen::Domain::pause() {
  _xenctrl.pause_domain(*this);
}

void xd::xen::Domain::unpause() {
  _xenctrl.unpause_domain(*this);
}
