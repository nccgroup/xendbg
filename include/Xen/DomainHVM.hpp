//
// Created by Spencer Michaels on 9/26/18.
//

#ifndef XENDBG_DOMAINHVM_HPP
#define XENDBG_DOMAINHVM_HPP

#include "Domain.hpp"

namespace xd::xen {

  class DomainHVM : public Domain {
  public:
    DomainHVM(DomID domid, XenEventChannel &xenevtchn, XenCtrl &xenctrl,
        XenForeignMemory &xenforiegnmemory, XenStore &xenstore);

    xd::reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id = 0) const override;
    void set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id = 0) const override;

    void set_debugging(bool enabled, VCPU_ID vcpu_id = 0) const;
    void set_single_step(bool enabled, VCPU_ID vcpu_id = 0) const;

    XenEventChannel::RingPageAndPort enable_monitor() const;
    void disable_monitor() const;

    void monitor_software_breakpoint(bool enable);
    void monitor_debug_exceptions(bool enable, bool sync);
    void monitor_cpuid(bool enable);
    void monitor_descriptor_access(bool enable);
    void monitor_privileged_call(bool enable);

  private:
    struct hvm_hw_cpu get_cpu_context_hvm(VCPU_ID vcpu_id) const;
    void set_cpu_context_hvm(struct hvm_hw_cpu context, VCPU_ID vcpu_id) const;

    static RegistersX86_64 convert_regs_from_pv64(const vcpu_guest_context_any_t &pv);
    static vcpu_guest_context_any_t convert_regs_to_pv64(const RegistersX86_64 &regs, vcpu_guest_context_any_t pv);
    static RegistersX86_32 convert_regs_from_pv32(const vcpu_guest_context_any_t &pv);
    static vcpu_guest_context_any_t convert_regs_to_pv32(const RegistersX86_32 &regs, vcpu_guest_context_any_t pv);
  };

}

#endif //XENDBG_DOMAINHVM_HPP
