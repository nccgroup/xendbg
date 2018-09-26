//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGSESSIONHVM_HPP
#define XENDBG_DEBUGSESSIONHVM_HPP

#include <optional>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <capstone/capstone.h>

#include <Xen/Domain.hpp>
#include <Util/overloaded.hpp>
#include <UV/UVLoop.hpp>

#include "DebugSession.hpp"

namespace xd::dbg {

  class DebugSessionHVM : public DebugSession {
  private:
    using BreakpointMap = std::unordered_map<xen::Address, uint8_t>;

  public:
    DebugSessionHVM(uv::UVLoop &loop, xen::Domain domain);
    ~DebugSessionHVM() override;

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


#endif //XENDBG_DEBUGSESSIONHVM_HPP
