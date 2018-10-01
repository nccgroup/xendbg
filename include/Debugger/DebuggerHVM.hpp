//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGGERHVM_HPP
#define XENDBG_DEBUGGERHVM_HPP

#include <optional>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <capstone/capstone.h>
#include <uvw.h>

#include <Xen/Domain.hpp>
#include <Util/overloaded.hpp>

#include "Debugger.hpp"

namespace xd::dbg {

  class DebuggerHVM : public Debugger {
  private:
    using BreakpointMap = std::unordered_map<xen::Address, uint8_t>;

  public:
    DebuggerHVM(uvw::Loop &loop, xen::Domain domain);
    ~DebuggerHVM() override;

    void continue_() override;
    xen::Address single_step() override;
    std::optional<xen::Address> check_breakpoint_hit() override;

    std::vector<xen::Address> get_breakpoints() override;
    void insert_breakpoint(xen::Address address) override;
    void remove_breakpoint(xen::Address address) override;

    MaskedMemory read_memory_masking_breakpoints(xen::Address address, size_t length) override;
    void write_memory_retaining_breakpoints(xen::Address address, size_t length, void *data) override;

  private:
    BreakpointMap _breakpoints;
  };

}


#endif //XENDBG_DEBUGGERHVM_HPP
