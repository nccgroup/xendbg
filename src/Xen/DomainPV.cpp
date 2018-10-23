//
// Created by Spencer Michaels on 9/26/18.
//

#include <Xen/DomainPV.hpp>
#include <Xen/Xen.hpp>
#include <Util/overloaded.hpp>

using xd::reg::RegistersX86Any;
using xd::reg::x86_32::RegistersX86_32;
using xd::reg::x86_64::RegistersX86_64;
using xd::xen::DomainPV;
using xd::xen::PagePermissions;
using xd::util::overloaded;

#define X86_EFLAGS_TF 0x00000100

#define GET_PV(_regs, _pv, _reg) \
  _regs.get<_reg>() = _pv._reg;
#define GET_PV_USER(_regs, _pv, _reg) \
  _regs.get<_reg>() = _pv.user_regs._reg;
#define SET_PV(_regs, _pv, _reg) \
  _pv._reg = _regs.get<_reg>();
#define SET_PV_USER(_regs, _pv, _reg) \
  _pv.user_regs._reg = _regs.get<_reg>();

DomainPV::DomainPV(DomID domid, std::shared_ptr<Xen> xen)
  : Domain(domid, std::move(xen))
{
}

vcpu_guest_context_any_t DomainPV::get_cpu_context_raw(VCPU_ID vcpu_id) const {
  int err;
  vcpu_guest_context_any_t context_any;
  if ((err = xc_vcpu_getcontext(_xen->xenctrl.get(), _domid, (uint16_t)vcpu_id, &context_any))) {
    throw XenException("Failed to get PV CPU context for VCPU " +
                       std::to_string(vcpu_id) + " of domain " +
                       std::to_string(_domid), -err);
  }
  return context_any;
}

void DomainPV::set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id) const {
  const auto old_context_any = get_cpu_context_raw(vcpu_id);
  const int word_size = get_word_size();

  std::visit(util::overloaded {
      [&](const RegistersX86_64 &regs64) {
        if (word_size != sizeof(uint64_t))
          throw XenException("Mismatched word size!");
        const auto new_context = convert_regs_to_pv64(regs64, old_context_any);
        set_cpu_context_raw(new_context, vcpu_id);
      }, [&](const RegistersX86_32 &regs32) {
        if (word_size != sizeof(uint32_t))
          throw XenException("Mismatched word size!");
        const auto new_context = convert_regs_to_pv32(regs32, old_context_any);
        set_cpu_context_raw(new_context, vcpu_id);
      }}, regs);
}

void DomainPV::set_cpu_context_raw(vcpu_guest_context_any_t context, VCPU_ID vcpu_id) const {
  int err = xc_vcpu_setcontext(_xen->xenctrl.get(), _domid, vcpu_id, &context);

  if (err < 0) {
    throw XenException("Failed to set PV CPU context for VCPU " +
                       std::to_string(vcpu_id) + " of domain " +
                       std::to_string(_domid), -err);
  }
}

RegistersX86Any DomainPV::get_cpu_context(VCPU_ID vcpu_id) const {
  const auto context_any = get_cpu_context_raw(vcpu_id);
  const int word_size = get_word_size();

  if (word_size == sizeof(uint64_t)) {
    return convert_regs_from_pv64(context_any);
  } else if (word_size == sizeof(uint32_t)) {
    return convert_regs_from_pv32(context_any);
  } else {
    throw XenException(
        "Unsupported word size " + std::to_string(word_size) + " for domain " +
        std::to_string(_domid) + "!");
  }
}

void DomainPV::set_singlestep(bool enable, VCPU_ID vcpu_id) const {
  auto context_any = get_cpu_context(vcpu_id);
  std::visit(util::overloaded {
    [enable](reg::x86_64::RegistersX86_64 &context) {
      auto &flags = context.get<reg::x86_64::rflags>();
      if (enable)
        flags |= X86_EFLAGS_TF;
      else
        flags &= ~X86_EFLAGS_TF;
    },
    [enable](reg::x86_32::RegistersX86_32 &context) {
      auto &flags = context.get<reg::x86_32::eflags>();
      if (enable)
        flags |= X86_EFLAGS_TF;
      else
        flags &= ~X86_EFLAGS_TF;
    }
  }, context_any);

  set_cpu_context(context_any, vcpu_id);
}

RegistersX86_64 DomainPV::convert_regs_from_pv64(const vcpu_guest_context_any_t &pv) {
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

  regs.get<cr0>() = pv.c.ctrlreg[0];
  regs.get<cr3>() = pv.c.ctrlreg[3];
  regs.get<cr4>() = pv.c.ctrlreg[4];

  regs.get<msr_efer>() = 0; // TODO

  return regs;
}

vcpu_guest_context_any_t DomainPV::convert_regs_to_pv64(const RegistersX86_64 &regs, vcpu_guest_context_any_t pv) {
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

  pv.c.ctrlreg[0] = regs.get<cr0>();
  pv.c.ctrlreg[3] = regs.get<cr3>();
  pv.c.ctrlreg[4] = regs.get<cr4>();

  return pv;
}

RegistersX86_32 DomainPV::convert_regs_from_pv32(const vcpu_guest_context_any_t &pv) {
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

  regs.get<cr0>() = pv.c.ctrlreg[0];
  regs.get<cr3>() = pv.c.ctrlreg[3];
  regs.get<cr4>() = pv.c.ctrlreg[4];

  regs.get<msr_efer>() = 0; // TODO

  return regs;
}

vcpu_guest_context_any_t DomainPV::convert_regs_to_pv32(const RegistersX86_32 &regs, vcpu_guest_context_any_t pv) {
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

  pv.c.ctrlreg[0] = regs.get<cr0>();
  pv.c.ctrlreg[3] = regs.get<cr3>();
  pv.c.ctrlreg[4] = regs.get<cr4>();

  return pv;
}
