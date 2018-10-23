//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

#include <capstone/capstone.h>
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
    xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn)
  : _domain(std::move(domain)), Debugger(_domain),
    _monitor(std::make_shared<HVMMonitor>(xendevicemodel, xenevtchn, loop, _domain)),
    _is_continuing(false)
{
}

void DebuggerHVM::attach() {
  Debugger::attach();
  _monitor->on_event([this](auto event) {
    const auto stop_and_signal = [&](Domain &domain) {
      domain.pause();
      domain.pause_vcpu(event.vcpu_id);
      domain.unpause();
      did_stop(SIGTRAP, event.vcpu_id);
    };

    bool was_continuing = _is_continuing;
    _is_continuing = false;

    if (event.reason == VM_EVENT_REASON_SINGLESTEP) {
      std::cout << "SS" << std::endl;
      if (was_continuing) {
        if (_last_single_step_breakpoint_addr) {
          insert_breakpoint(*_last_single_step_breakpoint_addr);
          _last_single_step_breakpoint_addr = std::nullopt;
        }
      } else {
        stop_and_signal(_domain);
      }
      _domain.set_singlestep(false, get_vcpu_id());
    } if (event.reason == VM_EVENT_REASON_SOFTWARE_BREAKPOINT) {
      stop_and_signal(_domain);
    }
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
  _domain.pause_all_vcpus();
  _domain.set_singlestep(true, vcpu);
  _domain.unpause_vcpu(vcpu);
  _domain.unpause();
}

void DebuggerHVM::insert_watchpoint(xen::Address address, uint32_t bytes, xenmem_access_t access) {
  _domain.set_mem_access(access, address >> XC_PAGE_SHIFT, bytes / XC_PAGE_SIZE);
}

void DebuggerHVM::remove_watchpoint(xen::Address address, uint32_t bytes, xenmem_access_t /*access*/) {
  _domain.set_mem_access(XENMEM_access_n, address >> XC_PAGE_SHIFT, bytes / XC_PAGE_SIZE);
}
