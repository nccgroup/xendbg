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

DebuggerHVM::DebuggerHVM(uvw::Loop &loop, DomainHVM domain,
    xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn)
  : DebuggerImpl<DomainHVM, uint8_t, X86_INT3>(std::move(domain)),
    _monitor(xendevicemodel, xenevtchn, loop, _domain)
{
}

void DebuggerHVM::on_breakpoint_hit(OnBreakpointHitFn on_breakpoint_hit) {
  _monitor.on_software_breakpoint([this, on_breakpoint_hit](const auto &req) {
    on_breakpoint_hit(req.data.regs.x86.rip);
    _monitor.stop();
  });
  _monitor.start();
}
