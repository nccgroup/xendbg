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
using xd::xen::DomainPV;

DebuggerPV::DebuggerPV(uvw::Loop &loop, DomainPV domain)
  : DebuggerImpl<DomainPV, uint16_t, X86_INFINITE_LOOP>(std::move(domain)),
    _timer(loop.resource<uvw::TimerHandle>())
{
}

void DebuggerPV::on_breakpoint_hit(OnBreakpointHitFn on_breakpoint_hit) {
  _timer->data(shared_from_this()); // TODO
  _timer->on<uvw::TimerEvent>([on_breakpoint_hit](const auto &event, auto &handle) {
    auto self = handle.template data<DebuggerPV>();
    auto address = self->check_breakpoint_hit();
    if (address) {
      handle.stop();
      on_breakpoint_hit(*address);
    }
    return address.has_value();
  });

  _timer->start(uvw::TimerHandle::Time(100), uvw::TimerHandle::Time(100));
}
