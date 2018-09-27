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
    struct hvm_hw_cpu get_cpu_context_raw(VCPU_ID vcpu_id) const;
    void set_cpu_context_raw(struct hvm_hw_cpu context, VCPU_ID vcpu_id) const;

    static reg::RegistersX86Any convert_regs_from_hvm(const struct hvm_hw_cpu &hvm);
    static struct hvm_hw_cpu convert_regs_to_hvm(const reg::x86_64::RegistersX86_64 &regs, hvm_hw_cpu hvm);
  };

}

#endif //XENDBG_DOMAINHVM_HPP
