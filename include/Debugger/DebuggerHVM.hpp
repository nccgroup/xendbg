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

#include <Xen/DomainHVM.hpp>

#include "Debugger.hpp"

namespace xd::dbg {

  class DebuggerHVM : public Debugger {
  private:
    using BreakpointMap = std::unordered_map<xen::Address, uint8_t>;

  public:
    DebuggerHVM(uvw::Loop &loop, xen::DomainHVM &domain);

    void continue_() override;
    xen::Address single_step() override;
    std::optional<xen::Address> check_breakpoint_hit() override;

    void cleanup() override;
    void insert_breakpoint(xen::Address address) override;
    void remove_breakpoint(xen::Address address) override;

    MaskedMemory read_memory_masking_breakpoints(xen::Address address, size_t length) override;
    void write_memory_retaining_breakpoints(xen::Address address, size_t length, void *data) override;

  private:
    xen::DomainHVM &_domain;
    BreakpointMap _breakpoints;
  };

}


#endif //XENDBG_DEBUGGERHVM_HPP
