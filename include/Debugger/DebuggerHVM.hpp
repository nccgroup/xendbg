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
    DebuggerHVM(xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn,
        uvw::Loop &loop, xen::DomainHVM domain);

    void on_breakpoint_hit(Debugger::OnBreakpointHitFn on_breakpoint_hit) override;

  private:
    xen::HVMMonitor _monitor;
  };

}


#endif //XENDBG_DEBUGGERHVM_HPP
