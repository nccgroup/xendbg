//
// Created by Spencer Michaels on 8/13/18.
//

#include <cstring>
#include <iostream>

#include "Domain.hpp"
#include "XenCtrl.hpp"
#include "XenException.hpp"

#include <sys/mman.h>

using reg::RegistersX86;
using reg::x86_32::RegistersX86_32;
using reg::x86_64::RegistersX86_64;
using xd::xen::DomInfo;
using xd::xen::Domain;
using xd::xen::MemInfo;
using xd::xen::WordSize;
using xd::xen::XenCtrl;
using xd::xen::XenException;

#define GET_HVM(_regs, _hvm, _reg) \
  _regs.get<_reg>() = _hvm._reg;
#define GET_HVM2(_regs, _hvm, _reg, _hvm_reg) \
  _regs.get<_reg>() = _hvm._hvm_reg;
#define SET_HVM(_regs, _hvm, _reg) \
  _hvm._reg = _regs.get<_reg>();
#define SET_HVM2(_regs, _hvm, _reg, _hvm_reg) \
  _hvm._hvm_reg = _regs.get<_reg>();
#define GET_PV(_regs, _pv, _reg) \
  _regs.get<_reg>() = _pv._reg;
#define GET_PV_USER(_regs, _pv, _reg) \
  _regs.get<_reg>() = _pv.user_regs._reg;
#define SET_PV(_regs, _pv, _reg) \
  _pv._reg = _regs.get<_reg>();
#define SET_PV_USER(_regs, _pv, _reg) \
  _pv.user_regs._reg = _regs.get<_reg>();

static RegistersX86 convert_from_hvm(const struct hvm_hw_cpu &hvm) {
  using namespace reg::x86_64;

  RegistersX86_64 regs;

  GET_HVM(regs, hvm, rax);
  GET_HVM(regs, hvm, rbx);
  GET_HVM(regs, hvm, rcx);
  GET_HVM(regs, hvm, rdx);
  GET_HVM(regs, hvm, rsp);
  GET_HVM(regs, hvm, rbp);
  GET_HVM(regs, hvm, rsi);
  GET_HVM(regs, hvm, rdi);
  GET_HVM(regs, hvm, r8);
  GET_HVM(regs, hvm, r9);
  GET_HVM(regs, hvm, r10);
  GET_HVM(regs, hvm, r11);
  GET_HVM(regs, hvm, r12);
  GET_HVM(regs, hvm, r13);
  GET_HVM(regs, hvm, r14);
  GET_HVM(regs, hvm, r15);
  GET_HVM(regs, hvm, rip);
  GET_HVM(regs, hvm, rflags);
  GET_HVM2(regs, hvm, fs, fs_base);
  GET_HVM2(regs, hvm, gs, gs_base);
  GET_HVM2(regs, hvm, cs, cs_base);
  GET_HVM2(regs, hvm, ds, ds_base);
  GET_HVM2(regs, hvm, ss, ss_base);

  return regs;
}

static hvm_hw_cpu convert_to_hvm(const RegistersX86_64 &regs) {
  using namespace reg::x86_64;

  struct hvm_hw_cpu hvm;
  memset(&hvm, 0x00, sizeof(struct hvm_hw_cpu));

  SET_HVM(regs, hvm, rax);
  SET_HVM(regs, hvm, rbx);
  SET_HVM(regs, hvm, rcx);
  SET_HVM(regs, hvm, rdx);
  SET_HVM(regs, hvm, rsp);
  SET_HVM(regs, hvm, rbp);
  SET_HVM(regs, hvm, rsi);
  SET_HVM(regs, hvm, rdi);
  SET_HVM(regs, hvm, r8);
  SET_HVM(regs, hvm, r9);
  SET_HVM(regs, hvm, r10);
  SET_HVM(regs, hvm, r11);
  SET_HVM(regs, hvm, r12);
  SET_HVM(regs, hvm, r13);
  SET_HVM(regs, hvm, r14);
  SET_HVM(regs, hvm, r15);
  SET_HVM(regs, hvm, rip);
  SET_HVM(regs, hvm, rflags);
  SET_HVM2(regs, hvm, fs, fs_base);
  SET_HVM2(regs, hvm, gs, gs_base);
  SET_HVM2(regs, hvm, cs, cs_base);
  SET_HVM2(regs, hvm, ds, ds_base);
  SET_HVM2(regs, hvm, ss, ss_base);

  return hvm;
}

static RegistersX86_64 convert_from_pv64(const vcpu_guest_context_x86_64_t &pv) {
  using namespace reg::x86_64;

  RegistersX86_64 regs;

  GET_PV_USER(regs, pv, rax);
  GET_PV_USER(regs, pv, rbx);
  GET_PV_USER(regs, pv, rcx);
  GET_PV_USER(regs, pv, rdx);
  GET_PV_USER(regs, pv, rsp);
  GET_PV_USER(regs, pv, rbp);
  GET_PV_USER(regs, pv, rsi);
  GET_PV_USER(regs, pv, rdi);
  GET_PV_USER(regs, pv, r8);
  GET_PV_USER(regs, pv, r9);
  GET_PV_USER(regs, pv, r10);
  GET_PV_USER(regs, pv, r11);
  GET_PV_USER(regs, pv, r12);
  GET_PV_USER(regs, pv, r13);
  GET_PV_USER(regs, pv, r14);
  GET_PV_USER(regs, pv, r15);
  GET_PV_USER(regs, pv, rip);
  GET_PV_USER(regs, pv, rflags);
  GET_PV_USER(regs, pv, fs);
  GET_PV_USER(regs, pv, gs);
  GET_PV_USER(regs, pv, cs);
  GET_PV_USER(regs, pv, ds);
  GET_PV_USER(regs, pv, ss);

  return regs;
}

static vcpu_guest_context_x86_64_t convert_to_pv64(const RegistersX86_64 &regs) {
  using namespace reg::x86_64;

  vcpu_guest_context_x86_64_t pv;
  memset(&pv, 0x00, sizeof(vcpu_guest_context_x86_64_t));

  SET_PV_USER(regs, pv, rax);
  SET_PV_USER(regs, pv, rbx);
  SET_PV_USER(regs, pv, rcx);
  SET_PV_USER(regs, pv, rdx);
  SET_PV_USER(regs, pv, rsp);
  SET_PV_USER(regs, pv, rbp);
  SET_PV_USER(regs, pv, rsi);
  SET_PV_USER(regs, pv, rdi);
  SET_PV_USER(regs, pv, r8);
  SET_PV_USER(regs, pv, r9);
  SET_PV_USER(regs, pv, r10);
  SET_PV_USER(regs, pv, r11);
  SET_PV_USER(regs, pv, r12);
  SET_PV_USER(regs, pv, r13);
  SET_PV_USER(regs, pv, r14);
  SET_PV_USER(regs, pv, r15);
  SET_PV_USER(regs, pv, rip);
  SET_PV_USER(regs, pv, rflags);
  SET_PV_USER(regs, pv, fs);
  SET_PV_USER(regs, pv, gs);
  SET_PV_USER(regs, pv, cs);
  SET_PV_USER(regs, pv, ds);
  SET_PV_USER(regs, pv, ss);

  return pv;
}

static RegistersX86_32 convert_from_pv32(const vcpu_guest_context_x86_32_t &pv) {
  using namespace reg::x86_32;

  RegistersX86_32 regs;

  GET_PV_USER(regs, pv, eax);
  GET_PV_USER(regs, pv, ebx);
  GET_PV_USER(regs, pv, ecx);
  GET_PV_USER(regs, pv, edx);
  GET_PV_USER(regs, pv, edi);
  GET_PV_USER(regs, pv, esi);
  GET_PV_USER(regs, pv, ebp);
  GET_PV_USER(regs, pv, esp);
  GET_PV_USER(regs, pv, ss);
  GET_PV_USER(regs, pv, eip);
  GET_PV_USER(regs, pv, eflags);
  GET_PV_USER(regs, pv, cs);
  GET_PV_USER(regs, pv, ds);
  GET_PV_USER(regs, pv, es);
  GET_PV_USER(regs, pv, fs);
  GET_PV_USER(regs, pv, gs);

  return regs;
}

static vcpu_guest_context_x86_32_t convert_to_pv32(const RegistersX86_32 &regs) {
  using namespace reg::x86_32;

  vcpu_guest_context_x86_32_t pv;
  memset(&pv, 0x00, sizeof(vcpu_guest_context_x86_32_t));

  SET_PV_USER(regs, pv, eax);
  SET_PV_USER(regs, pv, ebx);
  SET_PV_USER(regs, pv, ecx);
  SET_PV_USER(regs, pv, edx);
  SET_PV_USER(regs, pv, edi);
  SET_PV_USER(regs, pv, esi);
  SET_PV_USER(regs, pv, ebp);
  SET_PV_USER(regs, pv, esp);
  SET_PV_USER(regs, pv, ss);
  SET_PV_USER(regs, pv, eip);
  SET_PV_USER(regs, pv, eflags);
  SET_PV_USER(regs, pv, cs);
  SET_PV_USER(regs, pv, ds);
  SET_PV_USER(regs, pv, es);
  SET_PV_USER(regs, pv, fs);
  SET_PV_USER(regs, pv, gs);

  return pv;
}

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

RegistersX86 XenCtrl::get_domain_cpu_context(const Domain &domain,
    VCPU_ID vcpu_id) const
{
  if (domain.get_info().hvm == 1) {
    auto context = get_domain_cpu_context_hvm(domain, vcpu_id);
    return convert_from_hvm(context);
  } else {
    auto context_any = get_domain_cpu_context_pv(domain, vcpu_id);
    const int word_size = get_domain_word_size(domain);
    if (word_size == sizeof(uint64_t)) {
      return convert_from_pv64(context_any.x64);
    } else if (word_size == sizeof(uint32_t)) {
      return convert_from_pv32(context_any.x32);
    } else {
      throw XenException(
          "Unsupported word size " + std::to_string(word_size) + " for domain " +
          std::to_string(domain.get_domid()) + "!");
    }
  }
}

void XenCtrl::set_domain_cpu_context(const Domain &domain,
    const RegistersX86& regs, VCPU_ID vcpu_id) const
{
  if (domain.get_info().hvm == 1) {
    const auto regs64 = std::get<RegistersX86_64>(regs); // TODO
    const auto new_context = convert_to_hvm(regs64);
    set_domain_cpu_context_hvm(domain, new_context, vcpu_id);
  } else {
    const auto context_any = get_domain_cpu_context_pv(domain, vcpu_id);
    auto new_context = context_any;

    const int word_size = get_domain_word_size(domain);
    // TODO
    /*
    std::visit(
      [&](const RegistersX86_64 &regs64) {
        if (word_size != sizeof(uint64_t))
          throw XenException("Mismatched word size!");

        const auto new_regs = convert_to_pv64(regs64);
        new_context.x64.user_regs = new_regs.user_regs;
        set_domain_cpu_context_pv(domain, new_context, vcpu_id);
      }, [&](const RegistersX86_32 &regs32) {
        if (word_size != sizeof(uint32_t))
          throw XenException("Mismatched word size!");

        const auto new_regs = convert_to_pv32(regs32);
        new_context.x32.user_regs = new_regs.user_regs;
        set_domain_cpu_context_pv(domain, new_context, vcpu_id);
      }, regs);
      */
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
  auto xenctrl_ptr = _xenctrl.get();
  auto deleter = [xenctrl_ptr](xc_domain_meminfo *p) {
    xc_unmap_domain_meminfo(xenctrl_ptr, p);
  };

  auto meminfo =
    std::unique_ptr<xc_domain_meminfo, decltype(deleter)>(
      new xc_domain_meminfo, deleter);
  std::memset(meminfo.get(), 0, sizeof(xc_domain_meminfo));

  int err;
  xc_domain_meminfo minfo;
  if (err = xc_map_domain_meminfo(_xenctrl.get(), domain.get_domid(), meminfo.get())) {
    throw XenException(
      "Failed to map meminfo for domain " + std::to_string(domain.get_domid()),
        -err);
  }

  return meminfo;
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
  const auto dominfo = domain.get_info();
  if (dominfo.paused)
    return;

  int err;
  if (err = xc_domain_pause(_xenctrl.get(), domain.get_domid()))
    throw XenException(
        "Failed to pause domain " + std::to_string(domain.get_domid()), -err);
}

void XenCtrl::unpause_domain(const Domain &domain) const {
  const auto dominfo = domain.get_info();
  if (!dominfo.paused)
    return;

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
