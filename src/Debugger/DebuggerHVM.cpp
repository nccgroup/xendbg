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
  _domain.set_debugging(true);
  _monitor->start();
}

void DebuggerHVM::detach() {
  _monitor->stop();
  _domain.set_debugging(false);
  Base::detach();
}

void DebuggerHVM::continue_() {
  throw std::runtime_error("Not yet implemented!");
}

void DebuggerHVM::single_step() {
  _domain.pause();
  _domain.set_single_step(true);
  _domain.unpause();
}

void DebuggerHVM::on_stop(OnStopFn on_stop) {
  _monitor->on_software_breakpoint([on_stop](const auto &req) {
    on_stop(SIGTRAP); // TODO
  });
  _monitor->on_singlestep([this, on_stop](const auto &req) {
    on_stop(SIGTRAP); // TODO
    _domain.set_single_step(false);
  });
}
