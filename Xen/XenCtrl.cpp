//
// Created by Spencer Michaels on 8/13/18.
//

#include "Domain.hpp"
#include "XenCtrl.hpp"
#include "XenException.hpp"

#include "BridgeHeaders/xenguest.h"

#include <sys/mman.h>

using xd::xen::DomInfo;
using xd::xen::Domain;
using xd::xen::Registers;
using xd::xen::WordSize;
using xd::xen::XenCtrl;
using xd::xen::XenException;

xd::xen::XenCtrl::XenCtrl()
  : _xenctrl(xc_interface_open(nullptr, nullptr, 0), &xc_interface_close)
{
  if (!_xenctrl)
    throw XenException("Failed to open Xenctrl handle!");
}

XenCtrl::XenVersion XenCtrl::xen_version() {
  int version = xc_version(_xenctrl.get(), XENVER_version, NULL);
  return XenVersion {
    version >> 16,
    version & ((1 << 16) - 1)
  };
}

DomInfo XenCtrl::get_domain_info(Domain& domain) {
  xc_dominfo_t dominfo;
  int ret = xc_domain_getinfo(_xenctrl.get(), domain.get_domid(), 1, &dominfo);

  if (ret != 1 || dominfo.domid != domain.get_domid())
    throw std::runtime_error("Failed to get domain info!");
}

Registers XenCtrl::get_cpu_context(Domain &domain, VCPU_ID vcpu_id) {
  bool is_hvm = (domain.get_info().hvm == 1);

  if (is_hvm) {
    auto context = get_cpu_context_hvm(domain, vcpu_id);
    return convert_gp_registers_64(context, Registers64{});
  } else {
    auto context_any = get_cpu_context_pv(domain, vcpu_id);
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

WordSize xd::xen::XenCtrl::get_domain_word_size(Domain &domain) {
  unsigned int word_size;
  if (xc_domain_get_guest_width(_xenctrl.get(), domain.get_domid(), &word_size)) {
    throw XenException(
      "Failed to get word size for domain " + std::to_string(domain.get_domid()) + "!");
  }
  return word_size;
}

void XenCtrl::set_domain_debugging(Domain &domain, bool enable, VCPU_ID vcpu_id) {
  if (vcpu_id > domain.get_info().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") + " debugging for nonexistent VCPU " +
        std::to_string(vcpu_id) + " on domain " + std::to_string(domain.get_domid()) + "!");

  if (xc_domain_setdebugging(_xenctrl.get(), domain.get_domid(), (unsigned int)enable)) {
    throw XenException(
        "Failed to enable debugging on domain " + std::to_string(domain.get_domid()) + "!");
  }
}

void XenCtrl::set_domain_single_step(Domain &domain, bool enable, VCPU_ID vcpu_id) {
  uint32_t op = enable
      ? XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON
      : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

  if (vcpu_id > domain.get_info().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") + " single-step mode for nonexistent VCPU " +
        std::to_string(vcpu_id) + " on domain " + std::to_string(domain.get_domid()) + "!");

  if (xc_domain_debug_control(_xenctrl.get(), domain.get_domid(), op, vcpu_id)) {
    throw XenException(
        "Failed to " + std::string(enable ? "enable" : "disable") + " single-step mode for VCPU " +
        std::to_string(vcpu_id) + " on domain " + std::to_string(domain.get_domid()) + "!");
  }
}

void XenCtrl::pause_domain(Domain &domain) {
  if (xc_domain_pause(_xenctrl.get(), domain.get_domid()))
    throw XenException(
        "Failed pause domain " + std::to_string(domain.get_domid()) + "!");
}

void XenCtrl::unpause_domain(Domain &domain) {
  if (xc_domain_unpause(_xenctrl.get(), domain.get_domid()))
    throw XenException(
        "Failed unpause domain " + std::to_string(domain.get_domid()) + "!");
}

struct hvm_hw_cpu xd::xen::XenCtrl::get_cpu_context_hvm(Domain &domain, VCPU_ID vcpu_id) {
  struct hvm_hw_cpu cpu_context;
  if (xc_domain_hvm_getcontext_partial(_xenctrl.get(), domain.get_domid(), HVM_SAVE_CODE(CPU),
                                       (uint16_t)vcpu_id, &cpu_context, sizeof(cpu_context))) {
    throw XenException(
      "Failed get HVM CPU context for VCPU " + std::to_string(vcpu_id) + " of domain " +
      std::to_string(domain.get_domid()) + "!");
  }
  return cpu_context;
}

vcpu_guest_context_any_t XenCtrl::get_cpu_context_pv(Domain &domain, VCPU_ID vcpu_id) {
  vcpu_guest_context_any_t context_any;
  if (xc_vcpu_getcontext(_xenctrl.get(), domain.get_domid(), (uint16_t)vcpu_id, &context_any)) {
    throw XenException(
        "Failed get x32 PV CPU context for VCPU " + std::to_string(vcpu_id) + " of domain " +
        std::to_string(domain.get_domid()) + "!");
  }
  return context_any;
}

// See xen/tools/libxc/xc_offline_page.c:389
xen_pfn_t XenCtrl::pfn_to_mfn_pv(xen_pfn_t pfn, xen_pfn_t *pfn_to_gfn_table, WordSize word_size) {
  if (word_size == sizeof(uint64_t)) {
    return ((uint64_t*)pfn_to_gfn_table)[pfn];
  } else {
    uint32_t mfn = ((uint32_t*)pfn_to_gfn_table);
    return (mfn == ~0U) ? INVALID_MFN : mfn;
  }
}

std::unique_ptr<struct xc_domain_meminfo> XenCtrl::map_domain_meminfo(Domain &domain) {
  std::unique_ptr<struct xc_domain_meminfo> meminfo(new struct xc_domain_meminfo(),
      [this](struct xc_domain_meminfo *meminfo) {
        xc_unmap_domain_meminfo(_xenctrl.get(), meminfo);
      });

  if (xc_map_domain_meminfo(_xenctrl.get(), domain.get_domid(), meminfo.get())) {
    throw XenException("Failed to get meminfo!"); // TODO
  }
  return
}
