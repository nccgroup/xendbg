//
// Created by Spencer Michaels on 8/13/18.
//

#include <cstring>
#include <iostream>

#include <Util/overloaded.hpp>
#include <Xen/Domain.hpp>
#include <Xen/XenCtrl.hpp>
#include <Xen/XenException.hpp>

#include <sys/mman.h>

using xd::reg::RegistersX86Any;
using xd::reg::x86_32::RegistersX86_32;
using xd::reg::x86_64::RegistersX86_64;
using xd::xen::DomInfo;
using xd::xen::Domain;
using xd::xen::MemInfo;
using xd::xen::WordSize;
using xd::xen::XenCtrl;
using xd::xen::XenEventChannel;
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

static RegistersX86Any convert_from_hvm(const struct hvm_hw_cpu &hvm) {
  using namespace xd::reg::x86;
  using namespace xd::reg::x86_64;

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
  GET_HVM(regs, hvm, cr3);

  return regs;
}

static hvm_hw_cpu convert_to_hvm(const RegistersX86_64 &regs, hvm_hw_cpu hvm) {
  using namespace xd::reg::x86;
  using namespace xd::reg::x86_64;

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
  SET_HVM(regs, hvm, cr3);

  return hvm;
}

static RegistersX86_64 convert_from_pv64(const vcpu_guest_context_any_t &pv) {
  using namespace xd::reg::x86;
  using namespace xd::reg::x86_64;

  const auto &pv64 = pv.x64;
  RegistersX86_64 regs;

  GET_PV_USER(regs, pv64, rax);
  GET_PV_USER(regs, pv64, rbx);
  GET_PV_USER(regs, pv64, rcx);
  GET_PV_USER(regs, pv64, rdx);
  GET_PV_USER(regs, pv64, rsp);
  GET_PV_USER(regs, pv64, rbp);
  GET_PV_USER(regs, pv64, rsi);
  GET_PV_USER(regs, pv64, rdi);
  GET_PV_USER(regs, pv64, r8);
  GET_PV_USER(regs, pv64, r9);
  GET_PV_USER(regs, pv64, r10);
  GET_PV_USER(regs, pv64, r11);
  GET_PV_USER(regs, pv64, r12);
  GET_PV_USER(regs, pv64, r13);
  GET_PV_USER(regs, pv64, r14);
  GET_PV_USER(regs, pv64, r15);
  GET_PV_USER(regs, pv64, rip);
  GET_PV_USER(regs, pv64, rflags);
  GET_PV_USER(regs, pv64, fs);
  GET_PV_USER(regs, pv64, gs);
  GET_PV_USER(regs, pv64, cs);
  GET_PV_USER(regs, pv64, ds);
  GET_PV_USER(regs, pv64, ss);

  regs.get<cr3>() = pv.c.ctrlreg[3];

  return regs;
}

static vcpu_guest_context_any_t convert_to_pv64(const RegistersX86_64 &regs, vcpu_guest_context_any_t pv) {
  using namespace xd::reg::x86;
  using namespace xd::reg::x86_64;

  auto &pv64 = pv.x64;

  SET_PV_USER(regs, pv64, rax);
  SET_PV_USER(regs, pv64, rbx);
  SET_PV_USER(regs, pv64, rcx);
  SET_PV_USER(regs, pv64, rdx);
  SET_PV_USER(regs, pv64, rsp);
  SET_PV_USER(regs, pv64, rbp);
  SET_PV_USER(regs, pv64, rsi);
  SET_PV_USER(regs, pv64, rdi);
  SET_PV_USER(regs, pv64, r8);
  SET_PV_USER(regs, pv64, r9);
  SET_PV_USER(regs, pv64, r10);
  SET_PV_USER(regs, pv64, r11);
  SET_PV_USER(regs, pv64, r12);
  SET_PV_USER(regs, pv64, r13);
  SET_PV_USER(regs, pv64, r14);
  SET_PV_USER(regs, pv64, r15);
  SET_PV_USER(regs, pv64, rip);
  SET_PV_USER(regs, pv64, rflags);
  SET_PV_USER(regs, pv64, fs);
  SET_PV_USER(regs, pv64, gs);
  SET_PV_USER(regs, pv64, cs);
  SET_PV_USER(regs, pv64, ds);
  SET_PV_USER(regs, pv64, ss);

  pv.c.ctrlreg[3] = regs.get<cr3>();

  return pv;
}

static RegistersX86_32 convert_from_pv32(const vcpu_guest_context_any_t &pv) {
  using namespace xd::reg::x86;
  using namespace xd::reg::x86_32;

  RegistersX86_32 regs;
  const auto pv32 = pv.x32;

  GET_PV_USER(regs, pv32, eax);
  GET_PV_USER(regs, pv32, ebx);
  GET_PV_USER(regs, pv32, ecx);
  GET_PV_USER(regs, pv32, edx);
  GET_PV_USER(regs, pv32, edi);
  GET_PV_USER(regs, pv32, esi);
  GET_PV_USER(regs, pv32, ebp);
  GET_PV_USER(regs, pv32, esp);
  GET_PV_USER(regs, pv32, ss);
  GET_PV_USER(regs, pv32, eip);
  GET_PV_USER(regs, pv32, eflags);
  GET_PV_USER(regs, pv32, cs);
  GET_PV_USER(regs, pv32, ds);
  GET_PV_USER(regs, pv32, es);
  GET_PV_USER(regs, pv32, fs);
  GET_PV_USER(regs, pv32, gs);

  regs.get<cr3>() = pv.c.ctrlreg[3];

  return regs;
}

static vcpu_guest_context_any_t convert_to_pv32(const RegistersX86_32 &regs, vcpu_guest_context_any_t pv) {
  using namespace xd::reg::x86;
  using namespace xd::reg::x86_32;

  auto &pv32 = pv.x32;

  SET_PV_USER(regs, pv32, eax);
  SET_PV_USER(regs, pv32, ebx);
  SET_PV_USER(regs, pv32, ecx);
  SET_PV_USER(regs, pv32, edx);
  SET_PV_USER(regs, pv32, edi);
  SET_PV_USER(regs, pv32, esi);
  SET_PV_USER(regs, pv32, ebp);
  SET_PV_USER(regs, pv32, esp);
  SET_PV_USER(regs, pv32, ss);
  SET_PV_USER(regs, pv32, eip);
  SET_PV_USER(regs, pv32, eflags);
  SET_PV_USER(regs, pv32, cs);
  SET_PV_USER(regs, pv32, ds);
  SET_PV_USER(regs, pv32, es);
  SET_PV_USER(regs, pv32, fs);
  SET_PV_USER(regs, pv32, gs);

  pv.c.ctrlreg[3] = regs.get<cr3>();

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

/*
MemoryPermissions XenCtrl::get_domain_memory_permissions(
    const Domain &domain, Address address) const
{
  int err;
  xenmem_access_t permissions;
  xen_pfn_t pfn = address >> XC_PAGE_SHIFT;

  memset(&permissions, 0, sizeof(xenmem_access_t));
  if ((err = xc_get_mem_access(_xenctrl.get(), domain.get_domid(), pfn, &permissions))) {
    throw XenException("Failed to get memory permissions for PFN " +
        std::to_string(pfn) + " of domain " + std::to_string(domain.get_domid()), -err);
  }

  return permissions;
}
*/

struct hvm_hw_cpu XenCtrl::get_domain_cpu_context_hvm(const Domain &domain, VCPU_ID vcpu_id) const {
  int err;
  struct hvm_hw_cpu cpu_context;
  if ((err = xc_domain_hvm_getcontext_partial(_xenctrl.get(), domain.get_domid(),
        HVM_SAVE_CODE(CPU), (uint16_t)vcpu_id, &cpu_context, sizeof(cpu_context))))
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
  if ((err = xc_domain_hvm_getcontext_partial(_xenctrl.get(), domain.get_domid(),
        HVM_SAVE_CODE(CPU), (uint16_t)vcpu_id, &context, sizeof(context))))
  {
    throw XenException("Failed get HVM CPU context for VCPU " +
        std::to_string(vcpu_id) + " of domain " +
        std::to_string(domain.get_domid()), -err);
  }
}

vcpu_guest_context_any_t XenCtrl::get_domain_cpu_context_pv(const Domain &domain, VCPU_ID vcpu_id) const {
  int err;
  vcpu_guest_context_any_t context_any;
  if ((err = xc_vcpu_getcontext(_xenctrl.get(), domain.get_domid(), (uint16_t)vcpu_id,
        &context_any)))
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
  if ((err = xc_vcpu_setcontext(_xenctrl.get(), domain.get_domid(), (uint16_t)vcpu_id, 
        &context)))
  {
    throw XenException("Failed get PV CPU context for VCPU " +
        std::to_string(vcpu_id) + " of domain " +
        std::to_string(domain.get_domid()), -err);
  }
}
