//
// Created by Spencer Michaels on 9/26/18.
//

#include <Xen/DomainHVM.hpp>

#define GET_PV(_regs, _pv, _reg) \
  _regs.get<_reg>() = _pv._reg;
#define GET_PV_USER(_regs, _pv, _reg) \
  _regs.get<_reg>() = _pv.user_regs._reg;
#define SET_PV(_regs, _pv, _reg) \
  _pv._reg = _regs.get<_reg>();
#define SET_PV_USER(_regs, _pv, _reg) \
  _pv.user_regs._reg = _regs.get<_reg>();

xd::reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id = 0) const {
  int err;
  vcpu_guest_context_any_t context_any;
  if ((err = xc_vcpu_getcontext(_xenctrl.get(), _domid, (uint16_t)vcpu_id, &context_any))) {
    throw XenException("Failed get PV CPU context for VCPU " +
                       std::to_string(vcpu_id) + " of domain " +
                       std::to_string(_domid), -err);
  }

  const int word_size = get_domain_word_size(domain);
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

void set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id = 0) const {
  int err;
  struct hvm_hw_cpu old_context_any;
  if ((err = xc_domain_hvm_getcontext_partial(_xenctrl.get(), _domid,
      HVM_SAVE_CODE(CPU), (uint16_t)vcpu_id, &old_context_any, sizeof(context))))
  {
    throw XenException("Failed get HVM CPU context for VCPU " +
                       std::to_string(vcpu_id) + " of domain " +
                       std::to_string(_domid), -err);
  }

  const int word_size = get_domain_word_size(domain);
  std::visit(util::overloaded {
      [&](const RegistersX86_64 &regs64) {
        if (word_size != sizeof(uint64_t))
          throw XenException("Mismatched word size!");
        const auto new_context = convert_regs_to_pv64(regs64, old_context_any);
        set_cpu_context_pv(domain, new_context, vcpu_id);
      }, [&](const RegistersX86_32 &regs32) {
        if (word_size != sizeof(uint32_t))
          throw XenException("Mismatched word size!");
        const auto new_context = convert_regs_to_pv32(regs32, old_context_any);
        set_cpu_context_pv(domain, new_context, vcpu_id);
      }}, regs);
}

void DomainHVM::set_debugging(bool enabled, VCPU_ID vcpu_id) const {
  if (vcpu_id > get_info().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") +
        " debugging for nonexistent VCPU " + std::to_string(vcpu_id) +
        " on domain " + std::to_string(_domid));

  int err;
  if ((err = xc_domain_setdebugging(_xenctrl.get(), _domid, (unsigned int)enable))) {
    throw XenException(
        "Failed to enable debugging on domain " +
        std::to_string(_domid), -err);
  }
}

void DomainHVM::set_single_step(bool enabled, VCPU_ID vcpu_id) const {
  uint32_t op = enable
                ? XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON
                : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

  if (vcpu_id > get_info().max_vcpu_id)
    throw XenException(
        "Tried to " + std::string(enable ? "enable" : "disable") +
        " single-step mode for nonexistent VCPU " + std::to_string(vcpu_id) +
        " on domain " + std::to_string(_domid));

  int err;
  if ((err = xc_domain_debug_control(_xenctrl.get(), _domid, op, vcpu_id))) {
    throw XenException(
        "Failed to " + std::string(enable ? "enable" : "disable") +
        " single-step mode for VCPU " + std::to_string(vcpu_id) + " on domain " +
        std::to_string(_domid), -err);
  }
}

XenEventChannel::RingPageAndPort DomainHVM::enable_monitor() const {
  uint32_t port;
  void *ring_page = xc_monitor_enable(_xenctrl.get(), _domid, &port);

  if (!ring_page) {
    switch (errno) {
      case EBUSY:
        throw XenException("Monitoring is already active for this domain!");
      case ENODEV:
        throw XenException("This domain does not support EPT!");
      default:
        throw XenException("Failed to enable monitoring: "
                           + std::string(std::strerror(errno)));
    }
  }

  return {
      .ring_page = ring_page,
      .port = port
  };
}

void DomainHVM::disable_monitor() const {
  xc_monitor_disable(_xenctrl.get(), _domid);
}

void DomainHVM::monitor_software_breakpoint(bool enable) {
  xc_monitor_software_breakpoint(_xenctrl.get(), _domid, enable);
}

void DomainHVM::monitor_debug_exceptions(bool enable, bool sync) {
  xc_monitor_debug_exceptions(_xenctrl.get(), _domid, enable, sync);
}

void DomainHVM::monitor_cpuid(bool enable) {
  xc_monitor_cpuid(_xenctrl.get(), _domid, enable);
}

void DomainHVM::monitor_descriptor_access(bool enable) {
  xc_monitor_descriptor_access(_xenctrl.get(), _domid, enable);
}

void DomainHVM::monitor_privileged_call(bool enable) {
  xc_monitor_privileged_call(_xenctrl.get(), _domid, enable);
}

static RegistersX86_64 DomainHVM::convert_regs_regs_from_pv64(const vcpu_guest_context_any_t &pv) {
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

static vcpu_guest_context_any_t DomainHVM::convert_regs_regs_to_pv64(const RegistersX86_64 &regs, vcpu_guest_context_any_t pv) {
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

static RegistersX86_32 DomainHVM::convert_regs_regs_from_pv32(const vcpu_guest_context_any_t &pv) {
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

static vcpu_guest_context_any_t DomainHVM::convert_regs_regs_to_pv32(const RegistersX86_32 &regs, vcpu_guest_context_any_t pv) {
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
