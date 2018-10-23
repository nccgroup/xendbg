//
// Created by Spencer Michaels on 9/26/18.
//

#ifndef XENDBG_DOMAINHVM_HPP
#define XENDBG_DOMAINHVM_HPP

#include "Domain.hpp"
#include "XenEventChannel.hpp"

namespace xd::xen {

  class DomainHVM : public Domain {
  public:
    DomainHVM(DomID domid, std::shared_ptr<Xen> xen);

    reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id) const override;
    void set_cpu_context(reg::RegistersX86Any regs, VCPU_ID vcpu_id) const override;

    void set_singlestep(bool enabled, VCPU_ID vcpu_id) const override;

    XenEventChannel::RingPageAndPort enable_monitor() const;
    void disable_monitor() const;

    struct MonitorCapabilities {
      bool mov_to_msr, singlestep, software_breakpoint, descriptor_access,
           guest_request, debug_exception, cpuid_privileged_call;
    };

    MonitorCapabilities monitor_get_capabilities();
    void monitor_mov_to_msr(uint32_t msr, bool enable);
    void monitor_singlestep(bool enable);
    void monitor_software_breakpoint(bool enable);
    void monitor_debug_exceptions(bool enable, bool sync);
    void monitor_cpuid(bool enable);
    void monitor_descriptor_access(bool enable);
    void monitor_privileged_call(bool enable);
    void monitor_guest_request(bool enable, bool sync);

  private:
    struct hvm_hw_cpu get_cpu_context_raw(VCPU_ID vcpu_id) const;
    void set_cpu_context_raw(struct hvm_hw_cpu context, VCPU_ID vcpu_id) const;

    static reg::RegistersX86Any convert_regs_from_hvm(const struct hvm_hw_cpu &hvm);
    static struct hvm_hw_cpu convert_regs_to_hvm(const reg::x86_64::RegistersX86_64 &regs, hvm_hw_cpu hvm);
  };

}

#endif //XENDBG_DOMAINHVM_HPP
