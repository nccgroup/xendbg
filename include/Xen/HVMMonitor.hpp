//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_HVMMONITOR_HPP
#define XENDBG_HVMMONITOR_HPP

#include <functional>

#include <Xen/BridgeHeaders/ring.h>
#include <Xen/BridgeHeaders/vm_event.h>
#include <UV/UVLoop.hpp>
#include <UV/UVPoll.hpp>

#include "XenEventChannel.hpp"
#include "XenHandle.hpp"

namespace xd::xen::monitor {

  class Domain;

  class HVMMonitor {
  public:
    using OnEventFn = std::function<void()>; // TODO

    HVMMonitor(uv::UVLoop &loop, XenHandlePtr xen, const Domain &domain);
    ~HVMMonitor();

    void start(OnEventFn on_event);
    void stop();

  private:
    static void unmap_ring_page(void *ring_page);

    XenHandlePtr _xen;
    const Domain &_domain;
    xen::DomID _domid;
    XenEventChannel::Port _port;
    std::unique_ptr<void, decltype(&unmap_ring_page)> _ring_page;
    vm_event_back_ring_t _back_ring;
    uv::UVPoll _poll;

  private:
    vm_event_request_t get_request();
    void put_response(vm_event_response_t rsp);
    void read_events(OnEventFn on_event);
  };
}

#endif //XENDBG_HVMMONITOR_HPP
