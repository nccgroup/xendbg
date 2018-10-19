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

DebuggerHVM::DebuggerHVM(uvw::Loop &loop, std::shared_ptr<DomainHVM> domain,
    xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn)
  : Debugger(loop, domain),
    _domain(domain),
    _monitor(std::make_shared<HVMMonitor>(xendevicemodel, xenevtchn, loop, *_domain))
{
}

void DebuggerHVM::attach() {
  Debugger::attach();
  _monitor->start();
  insert_watchpoint(0xabc1, 0x1000, XENMEM_access_rwx);
  _monitor->on_event([this](auto event) {
    if (event.reason == VM_EVENT_REASON_SINGLESTEP && (event.flags & VM_EVENT_FLAG_VCPU_PAUSED)) {
      on_stop_internal(SIGTRAP);
    }
  });
}

void DebuggerHVM::detach() {
  _monitor->stop();
  Debugger::detach();
}

void DebuggerHVM::insert_watchpoint(xen::Address address, uint32_t bytes, xenmem_access_t access) {
  _domain->set_mem_access(access, address >> XC_PAGE_SHIFT, bytes / XC_PAGE_SIZE);
}

void DebuggerHVM::remove_watchpoint(xen::Address address, uint32_t bytes, xenmem_access_t /*access*/) {
  _domain->set_mem_access(XENMEM_access_n, address >> XC_PAGE_SHIFT, bytes / XC_PAGE_SIZE);
}
