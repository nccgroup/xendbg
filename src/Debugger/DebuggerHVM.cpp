//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

#include <spdlog/spdlog.h>

#include <Globals.hpp>

#include <Debugger/DebuggerHVM.hpp>
#include <Util/overloaded.hpp>

using xd::dbg::DebuggerHVM;
using xd::xen::Address;
using xd::xen::Domain;
using xd::xen::DomainHVM;
using xd::xen::HVMMonitor;

DebuggerHVM::DebuggerHVM(uvw::Loop &loop, DomainHVM domain,
    xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn,
    bool non_stop_mode)
  : _domain(std::move(domain)), Debugger(_domain),
    _monitor(std::make_shared<HVMMonitor>(xendevicemodel, xenevtchn, loop, _domain)),
    _is_continuing(false), _non_stop_mode(non_stop_mode)
{
}

void DebuggerHVM::on_event(vm_event_st event) {
  const auto pause_domain = [&](Domain &domain) {
    domain.pause();
    if (_non_stop_mode)
      domain.pause_vcpu(event.vcpu_id);
    else
      domain.pause_all_vcpus();
    domain.unpause();
  };

  if (_last_single_step_breakpoint_addr) {
    insert_breakpoint(*_last_single_step_breakpoint_addr);
    _last_single_step_breakpoint_addr = std::nullopt;
  }

  bool was_continuing = _is_continuing;
  _is_continuing = false;

  if (event.reason == VM_EVENT_REASON_SINGLESTEP) {
    if (!was_continuing) {
      pause_domain(_domain);
      did_stop(StopReasonBreakpoint(SIGTRAP, event.vcpu_id));
    }
    _domain.set_singlestep(false, get_vcpu_id());
  } else if (event.reason == VM_EVENT_REASON_SOFTWARE_BREAKPOINT) {
    pause_domain(_domain);
    did_stop(StopReasonBreakpoint(SIGTRAP, event.vcpu_id));
  } else if (event.reason == VM_EVENT_REASON_MEM_ACCESS) {
    pause_domain(_domain);
    const auto ma = event.u.mem_access;
    const auto address = (ma.gfn << XC_PAGE_SHIFT) + ma.offset;

    WatchpointType type;
    if (ma.flags & MEM_ACCESS_R) {
      type = WatchpointType::Read;
    } else if (ma.flags & MEM_ACCESS_W) {
      type = WatchpointType::Write;
    } else {
      type = WatchpointType::Access;
    }

    did_stop(StopReasonWatchpoint(SIGTRAP, event.vcpu_id, address, type));
  }
}

void DebuggerHVM::attach() {
  Debugger::attach();
  _monitor->on_event([this](auto event) {
    on_event(event);
  });
  _monitor->start();
}

void DebuggerHVM::detach() {
  _monitor->stop();
  Debugger::detach();
}

void DebuggerHVM::continue_() {
  _is_continuing = true;
  single_step();
}

void DebuggerHVM::single_step() {
  const auto vcpu = get_vcpu_id();

  const auto context = _domain.get_cpu_context(vcpu);
  const auto instr_ptr = reg::read_register<reg::x86_32::eip, reg::x86_64::rip>(context);
  if (_breakpoints.count(instr_ptr)) {
    _last_single_step_breakpoint_addr = instr_ptr;
    remove_breakpoint(instr_ptr);
  }

  // NOTE: The *domain* must be paused before individual VCPUs are paused/unpaused
  _domain.pause();
  if (!_non_stop_mode)
    _domain.pause_all_vcpus();

  _domain.set_singlestep(true, vcpu);

  if (!_non_stop_mode)
    _domain.unpause_vcpu(vcpu);
  _domain.unpause();
}

void DebuggerHVM::insert_watchpoint(xen::Address address, uint32_t bytes, WatchpointType type) {
  xenmem_access_t access = [type]() {
    switch (type) {
      case WatchpointType::Access:
        return XENMEM_access_n;
      case WatchpointType::Read:
        return XENMEM_access_wx;
      case WatchpointType::Write:
        return XENMEM_access_rx;
    }
  }();

  _domain.set_mem_access(access, address, bytes);
}

void DebuggerHVM::remove_watchpoint(xen::Address address, uint32_t bytes, WatchpointType /*type*/) {
  _domain.set_mem_access(XENMEM_access_rwx, address, bytes); // TODO: NOT SAFE
}
