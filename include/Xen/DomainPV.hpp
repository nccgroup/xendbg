//
// Created by Spencer Michaels on 9/26/18.
//

#ifndef XENDBG_DOMAINPV_HPP
#define XENDBG_DOMAINPV_HPP

#include "Domain.hpp"

namespace xd::xen {

  class DomainPV : public Domain {
  public:
    DomainPV(DomID domid, XenEventChannel &xenevtchn, XenCtrl &xenctrl,
        XenForeignMemory &xenforiegnmemory, XenStore &xenstore);

    reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id = 0) const override;
    void set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id = 0) const override;

  private:
    vcpu_guest_context_any_t get_cpu_context_raw(VCPU_ID vcpu_id) const;
    void set_cpu_context_raw(vcpu_guest_context_any_t context, VCPU_ID vcpu_id) const;

    static reg::x86_64::RegistersX86_64 convert_regs_from_pv64(
        const vcpu_guest_context_any_t &pv);
    static vcpu_guest_context_any_t convert_regs_to_pv64(
        const reg::x86_64::RegistersX86_64 &regs, vcpu_guest_context_any_t pv);
    static reg::x86_32::RegistersX86_32 convert_regs_from_pv32(
        const vcpu_guest_context_any_t &pv);
    static vcpu_guest_context_any_t convert_regs_to_pv32(
        const reg::x86_32::RegistersX86_32 &regs, vcpu_guest_context_any_t pv);
  };

}

#endif //XENDBG_DOMAINPV_HPP
