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
  : Debugger(_domain), _domain(std::move(domain)),
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
    const auto address = ma.gla;

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
