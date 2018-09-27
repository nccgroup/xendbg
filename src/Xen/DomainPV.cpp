//
// Created by Spencer Michaels on 9/26/18.
//

#include <Xen/DomainPV.hpp>

#define GET_HVM(_regs, _hvm, _reg) \
  _regs.get<_reg>() = _hvm._reg;
#define GET_HVM2(_regs, _hvm, _reg, _hvm_reg) \
  _regs.get<_reg>() = _hvm._hvm_reg;
#define SET_HVM(_regs, _hvm, _reg) \
  _hvm._reg = _regs.get<_reg>();
#define SET_HVM2(_regs, _hvm, _reg, _hvm_reg) \
  _hvm._hvm_reg = _regs.get<_reg>();

RegistersX86Any DomainPV::get_cpu_context(VCPU_ID vcpu_id) const {
  int err;
  struct hvm_hw_cpu cpu_context;
  if ((err = xc_domain_hvm_getcontext_partial(_xenctrl.get(), _domid,
      HVM_SAVE_CODE(CPU), (uint16_t)vcpu_id, &cpu_context, sizeof(cpu_context))))
  {
    throw XenException("Failed get HVM CPU context for VCPU " +
                       std::to_string(vcpu_id) + " of domain " +
                       std::to_string(_domid), -err);
  }

  return convert_regs_from_hvm(cpu_context);
}

void DomainPV::set_cpu_context(RegistersX86Any regs, VCPU_ID vcpu_id) const {
  const auto regs64 = std::get<RegistersX86_64>(regs);
  const auto old_cpu_context = get_cpu_context(vcpu_id);
  const auto new_context = convert_regs_to_hvm(regs64, old_cpu_context);

  int err;
  struct hvm_hw_cpu old_cpu_context;
  if ((err = xc_domain_hvm_getcontext_partial(_xenctrl.get(), _domid,
      HVM_SAVE_CODE(CPU), (uint16_t)vcpu_id, &new_context, sizeof(context))))
  {
    throw XenException("Failed get HVM CPU context for VCPU " +
                       std::to_string(vcpu_id) + " of domain " +
                       std::to_string(_domid), -err);
  }


  set_cpu_context_hvm(domain, new_context, vcpu_id);
}

RegistersX86Any DomainPV::convert_regs_from_hvm(const struct hvm_hw_cpu &hvm) {
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

hvm_hw_cpu DomainPV::convert_regs_to_hvm(const RegistersX86_64 &regs, hvm_hw_cpu hvm) {
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
