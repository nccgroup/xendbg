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

namespace xd::dbg {

  class DebuggerHVM : public Debugger {
  public:
    DebuggerHVM(uvw::Loop &loop, xen::DomainHVM domain,
        xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn,
        bool non_stop_mode);

    void attach() override;
    void detach() override;

    void continue_() override;
    void single_step() override;

    void insert_watchpoint(xen::Address address, uint32_t bytes, WatchpointType type) override;
    void remove_watchpoint(xen::Address address, uint32_t bytes, WatchpointType type) override;

  private:
    xen::DomainHVM _domain;
    std::shared_ptr<xen::HVMMonitor> _monitor;

    std::optional<xen::Address> _last_single_step_breakpoint_addr;
    bool _is_continuing;
    bool _non_stop_mode;

    void on_event(vm_event_st event);
  };

}


#endif //XENDBG_DEBUGGERHVM_HPP
