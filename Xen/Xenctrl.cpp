//
// Created by Spencer Michaels on 8/13/18.
//

#include "Domain.hpp"
#include "Xenctrl.hpp"
#include "XenException.hpp"

using xd::xen::DomInfo;
using xd::xen::Domain;
using xd::xen::WordSize;
using xd::xen::Xenctrl;
using xd::xen::XenException;

xd::xen::Xenctrl::Xenctrl()
  : _xenctrl(xc_interface_open(nullptr, nullptr, 0), &xc_interface_close)
{
  if (!_xenctrl)
    throw XenException("Failed to open Xenctrl handle!");
}

Xenctrl::XenVersion Xenctrl::xen_version() {
  int version = xc_version(_xenctrl.get(), XENVER_version, NULL);
  return XenVersion {
    version >> 16,
    version & ((1 << 16) - 1)
  };
}

DomInfo Xenctrl::get_domain_info(Domain& domain) {
  xc_dominfo_t dominfo;
  int ret = xc_domain_getinfo(_xenctrl.get(), domain.domid(), 1, &dominfo);

  if (ret != 1 || dominfo.domid != domain.domid())
    throw std::runtime_error("Failed to get domain info!");
}

void Xenctrl::get_cpu_context(Domain &domain, VCPU_ID vcpu_id) {
  bool is_hvm = (domain.info().hvm == 1);

  if (is_hvm) {
    auto context = get_cpu_context_hvm(domain, vcpu_id);
    // TODO
  } else {
    auto context_any = get_cpu_context_pv(domain, vcpu_id);
    const int word_size = get_domain_word_size(domain);

    if (word_size == 64) {
      auto context = context_any.x64;
      // TODO
    } else if (word_size == 32) {
      auto context = context_any.x32;
      // TODO
    } else {
      throw XenException(
          "Unsupported word size " + std::to_string(word_size) + " for domain " +
          std::to_string(domain.domid()) + "!");
    }
  }

}

WordSize xd::xen::Xenctrl::get_domain_word_size(Domain &domain) {
  unsigned int word_size;
  if (xc_domain_get_guest_width(_xenctrl.get(), domain.domid(), &word_size)) {
    throw XenException(
      "Failed to get word size for domain " + std::to_string(domain.domid()) + "!");
  }
  return word_size;
}

void Xenctrl::set_domain_debugging(Domain &domain, bool enable, VCPU_ID vcpu_id) {
  if (vcpu_id > domain.info().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") + " debugging for nonexistent VCPU " +
        std::to_string(vcpu_id) + " on domain " + std::to_string(domain.domid()) + "!");

  if (xc_domain_setdebugging(_xenctrl.get(), domain.domid(), (unsigned int)enable)) {
    throw XenException(
        "Failed to enable debugging on domain " + std::to_string(domain.domid()) + "!");
  }
}

void Xenctrl::set_domain_single_step(Domain &domain, bool enable, VCPU_ID vcpu_id) {
  uint32_t op = enable
      ? XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON
      : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

  if (vcpu_id > domain.info().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") + " single-step mode for nonexistent VCPU " +
        std::to_string(vcpu_id) + " on domain " + std::to_string(domain.domid()) + "!");

  if (xc_domain_debug_control(_xenctrl.get(), domain.domid(), op, vcpu_id)) {
    throw XenException(
        "Failed to " + std::string(enable ? "enable" : "disable") + " single-step mode for VCPU " +
        std::to_string(vcpu_id) + " on domain " + std::to_string(domain.domid()) + "!");
  }
}

void Xenctrl::pause_domain(Domain &domain) {
  if (xc_domain_pause(_xenctrl.get(), domain.domid()))
    throw XenException(
        "Failed pause domain " + std::to_string(domain.domid()) + "!");
}

void Xenctrl::unpause_domain(Domain &domain) {
  if (xc_domain_unpause(_xenctrl.get(), domain.domid()))
    throw XenException(
        "Failed unpause domain " + std::to_string(domain.domid()) + "!");
}

struct hvm_hw_cpu xd::xen::Xenctrl::get_cpu_context_hvm(Domain &domain, VCPU_ID vcpu_id) {
  struct hvm_hw_cpu cpu_context;
  if (xc_domain_hvm_getcontext_partial(_xenctrl.get(), domain.domid(), HVM_SAVE_CODE(CPU),
                                       (uint16_t)vcpu_id, &cpu_context, sizeof(cpu_context))) {
    throw XenException(
      "Failed get HVM CPU context for VCPU " + std::to_string(vcpu_id) + " of domain " +
      std::to_string(domain.domid()) + "!");
  }
  return cpu_context;
}

vcpu_guest_context_any_t Xenctrl::get_cpu_context_pv(Domain &domain, VCPU_ID vcpu_id) {
  vcpu_guest_context_any_t context_any;
  if (xc_vcpu_getcontext(_xenctrl.get(), domain.domid(), (uint16_t)vcpu_id, &context_any)) {
    throw XenException(
        "Failed get x32 PV CPU context for VCPU " + std::to_string(vcpu_id) + " of domain " +
        std::to_string(domain.domid()) + "!");
  }
  return context_any;
}

