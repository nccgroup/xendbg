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
using xd::xen::DomainHVM;
using xd::xen::HVMMonitor;

DebuggerHVM::DebuggerHVM(uvw::Loop &loop, DomainHVM domain,
    xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn)
  : Base(std::move(domain)), _monitor(std::make_shared<HVMMonitor>(xendevicemodel, xenevtchn, loop, _domain))
{
}

void DebuggerHVM::attach() {
  Base::attach();
  _monitor->start();
}

void DebuggerHVM::detach() {
  _monitor->stop();
  Base::detach();
}

void DebuggerHVM::continue_() {
  _is_continuing = true;
  single_step();
}

void DebuggerHVM::single_step() {
  const auto vcpu = get_vcpu_id();

  const auto context = _domain.get_cpu_context(vcpu);
  const auto instr_ptr = reg::read_register<
    reg::x86_32::eip, reg::x86_64::rip>(context);

  _last_single_step_vcpu_id = vcpu;

  _domain.pause_vcpus_except(vcpu);
  _domain.set_single_step(true, vcpu);
  _domain.set_debugging(true, vcpu);
  _domain.unpause();
}

void DebuggerHVM::on_stop(OnStopFn on_stop) {
  _monitor->on_software_breakpoint([this, on_stop](const auto &req) {
    _domain.pause();
    on_stop(SIGTRAP); // TODO
  });

  _monitor->on_singlestep([this, on_stop](const auto &req) {
    auto vcpu = (req.vcpu_id == -1)
        ? _last_single_step_vcpu_id
        : req.vcpu_id;

    _domain.set_single_step(false, vcpu);
    _domain.set_debugging(false, vcpu);

    if (_is_continuing) {
      _is_continuing = false;
      _domain.unpause();
    } else {
      _domain.unpause_vcpus_except(vcpu);
      set_vcpu_id(vcpu);
      on_stop(SIGTRAP); // TODO
    }
  });
}
