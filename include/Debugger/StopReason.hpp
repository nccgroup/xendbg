//
// Created by Spencer Michaels on 11/16/18.
//

#ifndef XENDBG_STOP_REASON_HPP
#define XENDBG_STOP_REASON_HPP

#include <variant>

#include <Xen/Common.hpp>

#include "WatchpointType.hpp"

namespace xd::dbg {

  struct StopReasonBase {
    StopReasonBase(int signal, xen::VCPU_ID vcpu_id)
      : signal(signal), vcpu_id(vcpu_id)
    {}

    int signal;
    xen::VCPU_ID vcpu_id;
  };

  struct StopReasonBreakpoint : public StopReasonBase {
    StopReasonBreakpoint(int signal, xen::VCPU_ID vcpu_id)
      : StopReasonBase(signal, vcpu_id)
    {}
  };

  struct StopReasonWatchpoint : public StopReasonBase {
    StopReasonWatchpoint(int signal, xen::VCPU_ID vcpu_id, xen::Address address,
        WatchpointType type)
      : StopReasonBase(signal, vcpu_id ), address(address), type(type)
    {}

    xen::Address address;
    WatchpointType type;
  };

  using StopReason = std::variant<
    StopReasonBreakpoint,
    StopReasonWatchpoint
  >;

}

#endif //XENDBG_STOP_REASON_HPP
