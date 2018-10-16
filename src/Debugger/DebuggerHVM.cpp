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
  : Base(std::move(domain)),
    _monitor(std::make_shared<HVMMonitor>(xendevicemodel, xenevtchn, loop, _domain)),
    _timer(loop.resource<uvw::TimerHandle>()), _last_stop_signal(SIGSTOP)
{
}

void DebuggerHVM::attach() {
  Base::attach();
  _domain.set_debugging(true);
  _timer->data(shared_from_this());
}

void DebuggerHVM::detach() {
  if (!_timer->closing())
    _timer->stop();
  _domain.set_debugging(false);
  Base::detach();
}

void DebuggerHVM::continue_() {
  // Single step first to get past the current BP, if any
  const auto prev_on_stop = _on_stop;
  _on_stop = [this, prev_on_stop](auto signal) {
    _on_stop = prev_on_stop;
    _timer->start(uvw::TimerHandle::Time(100), uvw::TimerHandle::Time(100));
    _domain.unpause();
  };

  single_step();
}

void DebuggerHVM::single_step() {
  auto vcpu = get_vcpu_id();

  std::cout << "get context 1" << std::endl;
  const auto context = _domain.get_cpu_context(vcpu);
  const auto instr_ptr = reg::read_register<reg::x86_32::eip, reg::x86_64::rip>(context);
  if (_breakpoints.count(instr_ptr)) {
    _last_single_step_breakpoint_addr = instr_ptr;
    remove_breakpoint(instr_ptr);
  }

  _domain.pause_vcpus_except(vcpu);
  _domain.set_single_step(true, vcpu);
  _last_single_step_vcpu_id = vcpu;

  _is_single_stepping = true;
  _timer->start(uvw::TimerHandle::Time(100), uvw::TimerHandle::Time(100));
  _domain.unpause();
}

void DebuggerHVM::on_stop(OnStopFn on_stop) {
  _on_stop = on_stop;

  _timer->on<uvw::TimerEvent>([this](const auto &event, auto &handle) {
    auto self = handle.template data<DebuggerHVM>();
    auto status = self->_domain.hypercall_domctl(XEN_DOMCTL_gdbsx_domstatus).gdbsx_domstatus;
    if (status.paused) {
      handle.stop();
      auto &domain = self->_domain;
      auto vcpu = (status.vcpu_id == -1)
                  ? self->_last_single_step_vcpu_id
                  : status.vcpu_id;

      // If we're stopping after a single step and there was a BP at the
      // address we came from, put it back
      if (self->_last_single_step_breakpoint_addr) {
        self->insert_breakpoint(*self->_last_single_step_breakpoint_addr);
        self->_last_single_step_breakpoint_addr = std::nullopt;
      }

      if (!self->_is_single_stepping) {
        /*
         * Otherwise, we came from continuing into a breakpoint.
         * HVM breaks are a bit weird; the guest pauses on the *next* instruction.
         * Since 0xCC BPs are 1 byte, we can just set RIP back by that amount to get
         * to the actual instruction that was broken on.
         */
        auto context_any = domain.get_cpu_context(vcpu);
        std::visit(util::overloaded {
            [](reg::x86_64::RegistersX86_64 &context) {
              context.get<reg::x86_64::rip>() -= 1;
            },
            [](reg::x86_32::RegistersX86_32 &context) {
              context.get<reg::x86_32::eip>() -= 1;
            }}, context_any);
        domain.set_cpu_context(context_any, vcpu);
      } else {
        self->_is_single_stepping = false;
        _domain.set_single_step(false, vcpu);
        domain.unpause_vcpus_except(vcpu);
      }

      self->set_vcpu_id(vcpu);
      self->on_stop_internal(SIGTRAP);
    }
  });
}

void DebuggerHVM::on_stop_internal(int signal) {
  _last_stop_signal = signal;
  if (_on_stop)
    _on_stop(signal);
}

