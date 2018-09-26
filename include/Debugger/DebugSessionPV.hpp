//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_DEBUGSESSIONPV_HPP
#define XENDBG_DEBUGSESSIONPV_HPP

#include <optional>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <capstone/capstone.h>

#include "DebugSession.hpp"
#include "../Xen/Domain.hpp"
#include "../../src/Util/overloaded.hpp"
#include "../UV/UVLoop.hpp"

namespace xd::dbg {

  class DebugSessionPV : public DebugSession {
  private:
    using InfiniteLoopMap = std::unordered_map<xen::Address, uint16_t>;

  public:
    DebugSessionPV(uv::UVLoop &loop, xen::Domain domain);
    ~DebugSessionPV() override;

    void continue_() override;
    xen::Address single_step() override;
    std::optional<xen::Address> check_breakpoint_hit() override;

    std::vector<xen::Address> get_breakpoints() override;
    void insert_breakpoint(xen::Address address) override;
    void remove_breakpoint(xen::Address address) override;

    MaskedMemory read_memory_masking_breakpoints(xen::Address address, size_t length) override;
    void write_memory_retaining_breakpoints(xen::Address address, size_t length, void *data) override;

  private:
    InfiniteLoopMap _infinite_loops;
  };

}


#endif //XENDBG_DEBUGSESSIONPV_HPP
