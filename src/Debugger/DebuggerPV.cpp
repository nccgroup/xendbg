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

#include <Debugger/DebuggerPV.hpp>
#include <Util/overloaded.hpp>
#include <xen/domctl.h>

#include <Debugger/StopReason.hpp>

using xd::dbg::DebuggerPV;
using xd::xen::Address;
using xd::xen::DomainPV;

DebuggerPV::DebuggerPV(uvw::Loop &loop, DomainPV domain)
  : Debugger(_domain), _domain(std::move(domain)),
    _timer(loop.resource<uvw::TimerHandle>()),
    _is_in_pre_continue_singlestep(false),
    _is_continuing(false)
{
}

void DebuggerPV::attach() {
  Debugger::attach();
  _domain.set_debugging(true, 0);

  _timer->data(shared_from_this());
  _timer->on<uvw::TimerEvent>([](const auto &event, auto &handle) {
    auto self = handle.template data<DebuggerPV>();
    auto status = self->_domain.hypercall_domctl(XEN_DOMCTL_gdbsx_domstatus).gdbsx_domstatus;

    if (!status.paused)
      return;

    handle.stop();

    auto &domain = self->_domain;
    auto vcpu = (status.vcpu_id == (size_t)-1)
        ? self->_last_single_step_vcpu_id
        : status.vcpu_id;

    // If we're stopping after a single step and there was a BP at the
    // address we came from, put it back
    if (self->_last_single_step_breakpoint_addr) {
      self->insert_breakpoint(*self->_last_single_step_breakpoint_addr);
      self->_last_single_step_breakpoint_addr = std::nullopt;
    }

    domain.set_singlestep(false, vcpu);

    if (self->_is_in_pre_continue_singlestep) {
      // Just continue again
      self->_is_in_pre_continue_singlestep = false;
      handle.start(uvw::TimerHandle::Time(10), uvw::TimerHandle::Time(100));
      domain.unpause();
    } else {
      /*
       * PV breaks are a bit weird; the guest pauses on the *next* instruction.
       * Since 0xCC BPs are 1 byte, we can just set RIP back by that amount to get
       * to the actual instruction that was broken on.
       */
      if (self->_is_continuing) {
        self->_is_continuing = false;

        auto context_any = domain.get_cpu_context(vcpu);
        std::visit(util::overloaded{
            [](reg::x86_64::RegistersX86_64 &context) {
              context.get<reg::x86_64::rip>() -= 1;
            },
            [](reg::x86_32::RegistersX86_32 &context) {
              context.get<reg::x86_32::eip>() -= 1;
            }}, context_any);

        domain.set_cpu_context(context_any, vcpu);
      }

      self->did_stop(StopReasonBreakpoint(SIGTRAP, vcpu));
    }
  });
}

void DebuggerPV::detach() {
  if (!_timer->closing())
    _timer->stop();
  _domain.set_debugging(false, 0);
  Debugger::detach();
}

void DebuggerPV::continue_() {
  // Single step first to get past the current BP, if any
  _is_continuing = true;
  _is_in_pre_continue_singlestep = true;
  single_step();
}

void DebuggerPV::single_step() {
  auto vcpu = get_vcpu_id();

  const auto context = _domain.get_cpu_context(vcpu);
  const auto instr_ptr = reg::read_register<reg::x86_32::eip, reg::x86_64::rip>(context);
  if (_breakpoints.count(instr_ptr)) {
    _last_single_step_breakpoint_addr = instr_ptr;
    remove_breakpoint(instr_ptr);
  }

  _last_single_step_vcpu_id = vcpu;

  _domain.pause();
  _domain.pause_all_vcpus();
  _domain.set_singlestep(true, vcpu);
  _domain.unpause_vcpu(vcpu);
  _timer->start(uvw::TimerHandle::Time(10), uvw::TimerHandle::Time(100));
  _domain.unpause();
}

