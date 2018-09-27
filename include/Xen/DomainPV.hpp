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

    xd::reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id = 0) const override;
    void set_cpu_context(xd::reg::RegistersX86Any regs, VCPU_ID vcpu_id = 0) const override;

  private:
    vcpu_guest_context_any_t get_cpu_context_pv(VCPU_ID vcpu_id) const;
    void set_cpu_context_pv(vcpu_guest_context_any_t context, VCPU_ID vcpu_id) const;

    static RegistersX86Any convert_from_hvm(const struct hvm_hw_cpu &hvm);
    static hvm_hw_cpu convert_to_hvm(const RegistersX86_64 &regs, hvm_hw_cpu hvm);
  };

}

#endif //XENDBG_DOMAINPV_HPP
