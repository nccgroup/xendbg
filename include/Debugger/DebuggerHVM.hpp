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

#ifndef XENDBG_DEBUGGERHVM_HPP
#define XENDBG_DEBUGGERHVM_HPP

#include <optional>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include <uvw.hpp>

#include <Xen/HVMMonitor.hpp>
#include <Xen/DomainHVM.hpp>

#include "Debugger.hpp"

namespace xd::dbg {

  class DebuggerHVM : public Debugger {
  public:
    DebuggerHVM(uvw::Loop &loop, xen::DomainHVM domain,
        xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn,
        bool non_stop_mode);
    ~DebuggerHVM() override = default;

    void attach() override;
    void detach() override;

    void continue_() override;
    void single_step() override;

    void insert_watchpoint(xen::Address address, uint32_t bytes, WatchpointType type) override;
    void remove_watchpoint(xen::Address address, uint32_t bytes, WatchpointType type) override;

  private:
    xen::DomainHVM _domain;
    std::shared_ptr<xen::HVMMonitor> _monitor;

    std::optional<xen::Address> _last_single_step_breakpoint_addr;
    bool _is_continuing;
    bool _non_stop_mode;

    void on_event(vm_event_st event);
  };

}


#endif //XENDBG_DEBUGGERHVM_HPP
