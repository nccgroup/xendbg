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

    void attach() override;
    void detach() override;

    void continue_() override;
    void single_step() override;

    void on_stop(Debugger::OnStopFn on_stop) override;
    int get_last_stop_signal() override { return _last_stop_signal; };

  private:
    std::shared_ptr<uvw::TimerHandle> _timer;
    OnStopFn _on_stop;
    int _last_stop_signal;

    std::optional<xen::Address> check_breakpoint_hit();

    void single_step_internal();
    void on_stop_internal(int signal);

    using Base = DebuggerImpl<xen::DomainPV, uint16_t, X86_INFINITE_LOOP>;
  };

}


#endif //XENDBG_DEBUGGERPV_HPP
