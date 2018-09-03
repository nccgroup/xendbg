//
// Created by Spencer Michaels on 8/13/18.
//

#include <cstring>
#include <iostream>

#include "Domain.hpp"
#include "XenCtrl.hpp"
#include "XenException.hpp"

#include <sys/mman.h>

using xd::xen::DomInfo;
using xd::xen::Domain;
using xd::xen::MemInfo;
using xd::xen::Registers;
using xd::xen::WordSize;
using xd::xen::XenCtrl;
using xd::xen::XenException;

xd::xen::XenCtrl::XenCtrl()
  : _xenctrl(xc_interface_open(nullptr, nullptr, 0), &xc_interface_close)
{
  if (!_xenctrl)
    throw XenException("Failed to open Xenctrl handle!", errno);
}

XenCtrl::XenVersion XenCtrl::get_xen_version() const {
  int version = xc_version(_xenctrl.get(), XENVER_version, NULL);
  return XenVersion {
    version >> 16,
    version & ((1 << 16) - 1)
  };
}

DomInfo XenCtrl::get_domain_info(const Domain &domain) const {
  xc_dominfo_t dominfo;
  int ret = xc_domain_getinfo(_xenctrl.get(), domain.get_domid(), 1, &dominfo);

  if (ret != 1 || dominfo.domid != domain.get_domid())
    throw XenException("Failed to get domain info!", errno);

  return dominfo;
}

Registers XenCtrl::get_domain_cpu_context(const Domain &domain, VCPU_ID vcpu_id) const {
  if (domain.get_info().hvm == 1) {
    auto context = get_domain_cpu_context_hvm(domain, vcpu_id);
    return convert_gp_registers_64(context, Registers64{});
  } else {
    auto context_any = get_domain_cpu_context_pv(domain, vcpu_id);
    const int word_size = get_domain_word_size(domain);
    if (word_size == sizeof(uint64_t)) {
      return convert_gp_registers_64(context_any.x64.user_regs, Registers64{});
    } else if (word_size == sizeof(uint32_t)) {
      return convert_gp_registers_32(context_any.x32.user_regs, Registers32{});
    } else {
      throw XenException(
          "Unsupported word size " + std::to_string(word_size) + " for domain " +
          std::to_string(domain.get_domid()) + "!");
    }
  }
}

void XenCtrl::set_domain_cpu_context(const Domain &domain, Registers regs, VCPU_ID vcpu_id) const {
  if (domain.get_info().hvm == 1) {
    const auto regs64 = std::get<Registers64>(regs);
    const auto context = get_domain_cpu_context_hvm(domain, vcpu_id);
    const auto new_context = convert_gp_registers_64(regs64, context);
    set_domain_cpu_context_hvm(domain, new_context, vcpu_id);
  } else {
    const auto context_any = get_domain_cpu_context_pv(domain, vcpu_id);
    auto new_context = context_any;

    const int word_size = get_domain_word_size(domain);
    if (word_size == sizeof(uint64_t)) {
      const auto regs64 = std::get<Registers64>(regs);
      new_context.x64.user_regs = convert_gp_registers_64(regs64, context_any.x64.user_regs);
      set_domain_cpu_context_pv(domain, new_context, vcpu_id);
    } else if (word_size == sizeof(uint32_t)) {
      const auto regs32 = std::get<Registers32>(regs);
      new_context.x32.user_regs = convert_gp_registers_32(regs32, context_any.x32.user_regs);
      set_domain_cpu_context_pv(domain, new_context, vcpu_id);
    } else {
      throw XenException(
          "Unsupported word size " + std::to_string(word_size) + " for domain " +
          std::to_string(domain.get_domid()) + "!");
    }
  }
}

WordSize xd::xen::XenCtrl::get_domain_word_size(const Domain &domain) const {
  int err;
  unsigned int word_size;
  if (err = xc_domain_get_guest_width(_xenctrl.get(), domain.get_domid(), &word_size)) {
    throw XenException(
      "Failed to get word size for domain " + std::to_string(domain.get_domid()),
        -err);
  }
  return word_size;
}

MemInfo XenCtrl::map_domain_meminfo(const Domain &domain) const {
  auto xenctrl = _xenctrl;
  auto deleter = [xenctrl](xc_domain_meminfo *p) {
    xc_unmap_domain_meminfo(xenctrl.get(), p);
  };

  const auto meminfo = new struct xc_domain_meminfo;
  std::memset(meminfo, 0, sizeof(struct xc_domain_meminfo));

  int err;
  if (err = xc_map_domain_meminfo(_xenctrl.get(), domain.get_domid(), meminfo)) {
    throw XenException(
      "Failed to map meminfo for domain " + std::to_string(domain.get_domid()),
        -err);
  }

  return std::unique_ptr<xc_domain_meminfo, decltype(deleter)>(
    meminfo, deleter);
}

void XenCtrl::set_domain_debugging(const Domain &domain, bool enable, VCPU_ID vcpu_id) const {
  if (vcpu_id > domain.get_info().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") +
        " debugging for nonexistent VCPU " + std::to_string(vcpu_id) +
        " on domain " + std::to_string(domain.get_domid()));

  int err;
  if (err = xc_domain_setdebugging(_xenctrl.get(), domain.get_domid(), (unsigned int)enable)) {
    throw XenException(
        "Failed to enable debugging on domain " +
          std::to_string(domain.get_domid()), -err);
  }
}

void XenCtrl::set_domain_single_step(const Domain &domain, bool enable, VCPU_ID vcpu_id) const {
  uint32_t op = enable
      ? XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON
      : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

  if (vcpu_id > domain.get_info().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") +
          " single-step mode for nonexistent VCPU " + std::to_string(vcpu_id) +
          " on domain " + std::to_string(domain.get_domid()));

  int err;
  if (err = xc_domain_debug_control(_xenctrl.get(), domain.get_domid(), op, vcpu_id)) {
    throw XenException(
        "Failed to " + std::string(enable ? "enable" : "disable") +
        " single-step mode for VCPU " + std::to_string(vcpu_id) + " on domain " +
        std::to_string(domain.get_domid()), -err);
  }
}

void XenCtrl::pause_domain(const Domain &domain) const {
  int err;
  if (err = xc_domain_pause(_xenctrl.get(), domain.get_domid()))
    throw XenException(
        "Failed to pause domain " + std::to_string(domain.get_domid()), -err);
}

void XenCtrl::unpause_domain(const Domain &domain) const {
  int err;
  if (err = xc_domain_unpause(_xenctrl.get(), domain.get_domid()))
    throw XenException(
        "Failed to unpause domain " + std::to_string(domain.get_domid()), -err);
}

struct hvm_hw_cpu XenCtrl::get_domain_cpu_context_hvm(const Domain &domain, VCPU_ID vcpu_id) const {
  int err;
  struct hvm_hw_cpu cpu_context;
  if (err = xc_domain_hvm_getcontext_partial(_xenctrl.get(), domain.get_domid(),
        HVM_SAVE_CODE(CPU), (uint16_t)vcpu_id, &cpu_context, sizeof(cpu_context)))
  {
    throw XenException("Failed get HVM CPU context for VCPU " +
        std::to_string(vcpu_id) + " of domain " +
        std::to_string(domain.get_domid()), -err);
  }
  return cpu_context;
}

void XenCtrl::set_domain_cpu_context_hvm(const Domain &domain, struct hvm_hw_cpu context,
    VCPU_ID vcpu_id) const
{
  int err;
  struct hvm_hw_cpu cpu_context;
  if (err = xc_domain_hvm_getcontext_partial(_xenctrl.get(), domain.get_domid(),
        HVM_SAVE_CODE(CPU), (uint16_t)vcpu_id, &context, sizeof(context)))
  {
    throw XenException("Failed get HVM CPU context for VCPU " +
        std::to_string(vcpu_id) + " of domain " +
        std::to_string(domain.get_domid()), -err);
  }
}

vcpu_guest_context_any_t XenCtrl::get_domain_cpu_context_pv(const Domain &domain, VCPU_ID vcpu_id) const {
  int err;
  vcpu_guest_context_any_t context_any;
  if (err = xc_vcpu_getcontext(_xenctrl.get(), domain.get_domid(), (uint16_t)vcpu_id,
        &context_any))
  {
    throw XenException("Failed get PV CPU context for VCPU " +
        std::to_string(vcpu_id) + " of domain " +
        std::to_string(domain.get_domid()), -err);
  }
  return context_any;
}

void XenCtrl::set_domain_cpu_context_pv(const Domain &domain,
    vcpu_guest_context_any_t context,VCPU_ID vcpu_id) const
{
  int err;
  vcpu_guest_context_any_t context_any;
  if (err = xc_vcpu_setcontext(_xenctrl.get(), domain.get_domid(), (uint16_t)vcpu_id, 
        &context))
  {
    throw XenException("Failed get PV CPU context for VCPU " +
        std::to_string(vcpu_id) + " of domain " +
        std::to_string(domain.get_domid()), -err);
  }
}
