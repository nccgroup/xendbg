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
using xd::xen::get_register_by_name;
using xd::xen::set_register_by_name;

Domain::Domain(XenHandle& xen, DomID domid)
    : _xen(xen), _domid(domid)
{
  get_info(); // Make sure the domain is behaving properly
}

std::string Domain::get_name() const {
  const auto path = "/local/domain/" + std::to_string(_domid) + "/name";
  return _xen.get_xenstore().read(path);
}

std::string Domain::get_kernel_path() const {
  const auto vm_path = "/local/domain/" + std::to_string(_domid) + "/vm";
  const auto vm = _xen.get_xenstore().read(vm_path);
  const auto kernel_path = vm + "/image/kernel";
  return _xen.get_xenstore().read(kernel_path);
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

void Domain::read_memory(Address address, void *data, size_t size) {
  hypercall_domctl(XEN_DOMCTL_gdbsx_guestmemio, [address, data, size](auto u) {
    auto& memio = u->gdbsx_guest_memio;
    memio.pgd3val = 0;
    memio.gva = address;
    memio.uva = (uint64_aligned_t)((unsigned long)data);
    memio.len = size;
    memio.gwr = 0;

    if (mlock(data, size))
      throw XenException("mlock failed!");
  }, [data, size]() {
    munlock(data, size);
  });
}

void Domain::write_memory(Address address, void *data, size_t size) {
  hypercall_domctl(XEN_DOMCTL_gdbsx_guestmemio, [address, data, size](auto u) {
    auto& memio = u->gdbsx_guest_memio;
    memio.pgd3val = 0;
    memio.gva = address;
    memio.uva = (uint64_aligned_t)((unsigned long)data);
    memio.len = size;
    memio.gwr = 1;

    if (mlock(data, size))
      throw XenException("mlock failed!");
  }, [data, size]() {
    munlock(data, size);
  });
}

MappedMemory Domain::map_memory(Address address, size_t size, int prot) const {
  return _xen.get_xen_foreign_memory().map(*this, address, size, prot);
}

uint64_t Domain::read_register(const std::string &name, VCPU_ID vcpu_id) {
  const auto regs = get_cpu_context(vcpu_id);
  return get_register_by_name(regs, name);
}

void Domain::write_register(const std::string &name, uint64_t value, VCPU_ID vcpu_id) {
  auto regs = get_cpu_context(vcpu_id);
  set_register_by_name(regs, name, value);
  set_cpu_context(regs, vcpu_id);
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
