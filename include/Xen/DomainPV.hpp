//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#ifndef XENDBG_DOMAINPV_HPP
#define XENDBG_DOMAINPV_HPP

#include "Domain.hpp"

namespace xd::xen {

  class DomainPV : public Domain {
  public:
    DomainPV(DomID domid, std::shared_ptr<Xen> xen);

    reg::RegistersX86Any get_cpu_context(VCPU_ID vcpu_id) const override;
    void set_cpu_context(reg::RegistersX86Any regs, VCPU_ID vcpu_id) const override;

    void set_singlestep(bool enabled, VCPU_ID vcpu_id) const override;

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
