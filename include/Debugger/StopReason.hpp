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
