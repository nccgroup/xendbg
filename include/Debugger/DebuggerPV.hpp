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

#define X86_INT3 0xCC

namespace xd::dbg {

  class DebuggerPV : public Debugger {
  public:
    DebuggerPV(uvw::Loop &loop, xen::DomainPV domain);

    void attach() override;
    void detach() override;

    void continue_() override;
    void single_step() override;

  private:
    xen::DomainPV _domain;
    std::shared_ptr<uvw::TimerHandle> _timer;
    bool _is_in_pre_continue_singlestep, _is_continuing;

    xen::VCPU_ID _last_single_step_vcpu_id;
    std::optional<xen::Address> _last_single_step_breakpoint_addr;
  };

}


#endif //XENDBG_DEBUGGERPV_HPP
