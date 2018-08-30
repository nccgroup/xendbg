//
// Created by Spencer Michaels on 8/13/18.
//

#include "Domain.hpp"

using xd::xen::Domain;
using xd::xen::DomInfo;
using xd::xen::Registers;
using xd::xen::MappedMemory;
using xd::xen::MemInfo;
using xd::xen::XenCtrl;
using xd::xen::XenHandle;

Domain::Domain(XenHandle& xen, DomID domid)
    : _xen(xen), _domid(domid)
{
  get_info(); // Make sure the domain is behaving properly
}

std::string xd::xen::Domain::get_name() const {
  const auto path = "/local/domain/" + std::to_string(_domid) + "/name";
  return _xen.get_xenstore().read(path);
}

DomInfo Domain::get_info() const {
  return _xen.get_xenctrl().get_domain_info(*this);
}

int Domain::get_word_size() const {
  return _xen.get_xenctrl().get_domain_word_size(*this);
}

MemInfo Domain::map_meminfo() const {
  return _xen.get_xenctrl().map_domain_meminfo(*this);
}

MappedMemory Domain::map_memory(Address address, size_t size, int prot) const {
  return _xen.get_xen_foreign_memory().map(*this, address, size, prot);
}

Registers xd::xen::Domain::get_cpu_context(VCPU_ID vcpu_id) const {
  return _xen.get_xenctrl().get_domain_cpu_context(*this, vcpu_id);
}

void xd::xen::Domain::set_cpu_context(Registers regs, VCPU_ID vcpu_id) const {
  _xen.get_xenctrl().set_domain_cpu_context(*this, regs, vcpu_id);
}

void xd::xen::Domain::set_debugging(bool enabled, VCPU_ID vcpu_id) const {
  _xen.get_xenctrl().set_domain_debugging(*this, enabled, vcpu_id);
}

void xd::xen::Domain::set_single_step(bool enabled, VCPU_ID vcpu_id) const {
  _xen.get_xenctrl().set_domain_single_step(*this, enabled, vcpu_id);
}

void xd::xen::Domain::pause() const {
  _xen.get_xenctrl().pause_domain(*this);
}

void xd::xen::Domain::unpause() const {
  _xen.get_xenctrl().unpause_domain(*this);
}
