//
// Created by Spencer Michaels on 8/28/18.
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
    DebuggerHVM(uvw::Loop &loop, std::shared_ptr<xen::DomainHVM> domain,
        xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn);

    void attach() override;
    void detach() override;

    void insert_watchpoint(xen::Address address, uint32_t bytes, xenmem_access_t access) override;
    void remove_watchpoint(xen::Address address, uint32_t bytes, xenmem_access_t access) override;

  private:
    std::shared_ptr<xen::DomainHVM> _domain;
    std::shared_ptr<xen::HVMMonitor> _monitor;
  };

}


#endif //XENDBG_DEBUGGERHVM_HPP
