//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGERPV_HPP
#define XENDBG_DEBUGGERPV_HPP

#include <optional>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include <uvw.hpp>

#include <Xen/DomainPV.hpp>

#include "Debugger.hpp"

#define X86_INFINITE_LOOP 0xFEEB

namespace xd::dbg {

  class DebuggerPV : public DebuggerImpl<xen::DomainPV, uint16_t, X86_INFINITE_LOOP> {
  public:
    DebuggerPV(uvw::Loop &loop, xen::DomainPV domain);
    ~DebuggerPV() = default;

    void on_breakpoint_hit(Debugger::OnBreakpointHitFn on_breakpoint_hit) override;

  private:
    std::shared_ptr<uvw::TimerHandle> _timer;
  };

}


#endif //XENDBG_DEBUGGERPV_HPP
