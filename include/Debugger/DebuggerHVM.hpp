//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGERHVM_HPP
#define XENDBG_DEBUGGERHVM_HPP

#include <optional>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include <uvw.hpp>

#include <Xen/HVMMonitor.hpp>
#include <Xen/DomainHVM.hpp>

#include "Debugger.hpp"

#define X86_INT3 0xCC

namespace xd::dbg {

  class DebuggerHVM : public DebuggerImpl<xen::DomainHVM, uint8_t, X86_INT3> {
  public:
    DebuggerHVM(uvw::Loop &loop, xen::DomainHVM domain,
        xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn);

    void attach() override;
    void detach() override;

    void continue_() override;
    void single_step() override;

    void on_stop(Debugger::OnStopFn on_stop) override;
    int get_last_stop_signal() override { return SIGSTOP; }; // TODO

  private:
    std::shared_ptr<uvw::TimerHandle> _timer;
    OnStopFn _on_stop;
    int _last_stop_signal;
    xen::VCPU_ID _last_single_step_vcpu_id;
    std::optional<xen::Address> _last_single_step_breakpoint_addr;
    bool _is_single_stepping;

    void on_stop_internal(int signal);

    using Base = DebuggerImpl<xen::DomainHVM, uint8_t, X86_INT3>;
  };

}


#endif //XENDBG_DEBUGGERHVM_HPP
