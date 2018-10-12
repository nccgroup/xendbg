//
// Created by Spencer Michaels on 8/28/18.
//

#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

#include <capstone/capstone.h>
#include <spdlog/spdlog.h>

#include <Globals.hpp>

#include <Debugger/DebuggerPV.hpp>
#include <Util/overloaded.hpp>

using xd::dbg::DebuggerPV;
using xd::xen::Address;
using xd::xen::DomainPV;

DebuggerPV::DebuggerPV(uvw::Loop &loop, DomainPV domain)
  : DebuggerImpl<DomainPV, uint16_t, X86_INFINITE_LOOP>(std::move(domain)),
    _timer(loop.resource<uvw::TimerHandle>()), _last_stop_signal(SIGSTOP)
{
}

void DebuggerPV::attach() {
  Base::attach();
  _timer->data(shared_from_this());
}

void DebuggerPV::detach() {
  if (!_timer->closing())
    _timer->stop();
  Base::detach();
}

void DebuggerPV::continue_() {
  // Single step first to move beyond the current breakpoint;
  // it will be removed during the step and replaced automatically.
  if (check_breakpoint_hit())
    single_step_internal();

  _timer->start(uvw::TimerHandle::Time(100), uvw::TimerHandle::Time(100));
  _domain.unpause();
}

void DebuggerPV::single_step() {
  single_step_internal();
  on_stop_internal(SIGTRAP);
}

void DebuggerPV::single_step_internal() {
    _domain.pause();

    // If there's already a breakpoint here, remove it temporarily so we can continue
    std::optional<xen::Address> orig_addr;
    if ((orig_addr = check_breakpoint_hit()))
      remove_breakpoint(*orig_addr);

    // For conditional branches, we need to insert EBFEs at both potential locations.
    const auto [dest1_addr, dest2_addr_opt] = get_address_of_next_instruction();
    bool dest1_had_il = (_breakpoints.count(dest1_addr) != 0);
    bool dest2_had_il = dest2_addr_opt && (_breakpoints.count(*dest2_addr_opt) != 0);

    insert_breakpoint(dest1_addr);
    if (dest2_addr_opt && !dest2_had_il)
      insert_breakpoint(*dest2_addr_opt);

    _domain.unpause();
    while (!check_breakpoint_hit());
    _domain.pause();

    // Remove each of our two infinite loops unless there is a
    // *manually-inserted* breakpoint at the corresponding address.
    if (!dest1_had_il)
      remove_breakpoint(dest1_addr);
    if (dest2_addr_opt && !dest2_had_il)
      remove_breakpoint(*dest2_addr_opt);

    // If there was a BP at the instruction we started at, put it back
    if (orig_addr)
      insert_breakpoint(*orig_addr);
}

void DebuggerPV::on_stop(OnStopFn on_stop) {
  _on_stop = on_stop;

  _timer->on<uvw::TimerEvent>([](const auto &event, auto &handle) {
    auto self = handle.template data<DebuggerPV>();
    auto address = self->check_breakpoint_hit();
    if (address) {
      handle.stop();
      self->_domain.pause();
      self->on_stop_internal(SIGTRAP); // TODO
    }
    return address.has_value();
  });
}

std::optional<Address> DebuggerPV::check_breakpoint_hit() {
  const auto address = reg::read_register<reg::x86_32::eip, reg::x86_64::rip>(
      _domain.get_cpu_context());
  const auto mem_handle = _domain.map_memory<uint16_t>(
      address, sizeof(uint16_t), PROT_READ);
  const auto mem = mem_handle.get();

  if (*mem == X86_INFINITE_LOOP && _breakpoints.count(address))
    return address;
  return std::nullopt;
}

void DebuggerPV::on_stop_internal(int signal) {
  _last_stop_signal = signal;
  if (_on_stop)
    _on_stop(signal);
}
