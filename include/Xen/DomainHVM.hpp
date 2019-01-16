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
