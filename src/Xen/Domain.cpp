//
// Created by Spencer Michaels on 8/13/18.
//

#include "BridgeHeaders/libxl.h"

#include "Domain.hpp"

using xd::reg::RegistersX86;
using xd::xen::Domain;
using xd::xen::DomInfo;
using xd::xen::MappedMemory;
using xd::xen::MemInfo;
using xd::xen::XenCtrl;
using xd::xen::XenHandle;
using xd::xen::MemoryPermissions;

Domain::Domain(const XenHandle& xen, DomID domid)
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

// TODO: This doesn't seem to have any effect.
/*
void Domain::reboot() const {
  libxl_ctx *ctx;
  libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, nullptr);
  libxl_domain_reboot(ctx, _domid);
  libxl_ctx_free(ctx);
}
*/

/*
void Domain::read_memory(Address address, void *data, size_t size) {
  hypercall_domctl(XEN_DOMCTL_gdbsx_guestmemio, [address, data, size](auto u) {
    auto& memio = u->gdbsx_guest_memio;
    memio.pgd3val = 0;
    memio.gva = address;
    memio.uva = (uint64_aligned_t)((unsigned long)data);
    memio.len = size;
    memio.gwr = 0;

    if (mlock(data, size))
      throw XenException("mlock failed!", errno);
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
      throw XenException("mlock failed!", errno);
  }, [data, size]() {
    munlock(data, size);
  });
}
*/

MappedMemory Domain::map_memory(Address address, size_t size, int prot) const {
  return _xen.get_xen_foreign_memory().map(*this, address, size, prot);
}

MemoryPermissions Domain::get_memory_permissions(Address address) const {
  return _xen.get_xenctrl().get_domain_memory_permissions(*this, address);
}

RegistersX86 Domain::get_cpu_context(VCPU_ID vcpu_id) const {
  return _xen.get_xenctrl().get_domain_cpu_context(*this, vcpu_id);
}

void Domain::set_cpu_context(RegistersX86 regs, VCPU_ID vcpu_id) const {
  _xen.get_xenctrl().set_domain_cpu_context(*this, regs, vcpu_id);
}

void Domain::set_debugging(bool enabled, VCPU_ID vcpu_id) const {
  _xen.get_xenctrl().set_domain_debugging(*this, enabled, vcpu_id);
}

void Domain::set_single_step(bool enabled, VCPU_ID vcpu_id) const {
  _xen.get_xenctrl().set_domain_single_step(*this, enabled, vcpu_id);
}

void Domain::pause() const {
  _xen.get_xenctrl().pause_domain(*this);
}

void Domain::unpause() const {
  _xen.get_xenctrl().unpause_domain(*this);
}

void Domain::shutdown(int reason) const {
  _xen.get_xenctrl().shutdown_domain(*this, reason);
}

void Domain::destroy() const {
  _xen.get_xenctrl().destroy_domain(*this);
}
