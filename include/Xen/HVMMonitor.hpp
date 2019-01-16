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

#ifndef XENDBG_HVMMONITOR_HPP
#define XENDBG_HVMMONITOR_HPP

#include <functional>
#include <memory>

#include <uvw.hpp>


#include "Common.hpp"
#include "DomainHVM.hpp"
#include "BridgeHeaders/ring.h"
#include "BridgeHeaders/vm_event.h"
#include "XenDeviceModel.hpp"
#include "XenEventChannel.hpp"

namespace xd::xen {

  class HVMMonitor : public std::enable_shared_from_this<HVMMonitor> {
  public:
    using OnEventFn = std::function<void(vm_event_request_t)>;

    HVMMonitor(xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn,
        uvw::Loop &loop, DomainHVM &domain);
    ~HVMMonitor();

    void start();
    void stop();

    void on_event(OnEventFn callback) {
      _on_event = std::move(callback);
    };

  private:
    static void unmap_ring_page(void *ring_page);

    xen::XenDeviceModel &_xendevicemodel;
    xen::XenEventChannel &_xenevtchn;
    DomainHVM &_domain;

    xen::DomID _domid;
    XenEventChannel::Port _port;
    std::unique_ptr<void, decltype(&unmap_ring_page)> _ring_page;
    vm_event_back_ring_t _back_ring;
    std::shared_ptr<uvw::PollHandle> _poll;

    OnEventFn _on_event;

  private:
    vm_event_request_t get_request();
    void put_response(vm_event_response_t rsp);
    void read_events();
  };
}

#endif //XENDBG_HVMMONITOR_HPP
