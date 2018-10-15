//
// Created by Spencer Michaels on 8/13/18.
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

    struct Capabilities {
      bool mov_to_msr, singlestep, software_breakpoint, descriptor_access,
           guest_request, _debug_exceptions, cpuid_privileged_call;
    };

    HVMMonitor(xen::XenDeviceModel &xendevicemodel, xen::XenEventChannel &xenevtchn,
        uvw::Loop &loop, DomainHVM &domain);
    ~HVMMonitor();

    void start();
    void stop();

    Capabilities get_capabilities();

    void on_software_breakpoint(OnEventFn callback) {
      _on_software_breakpoint = callback;
    };
    void on_singlestep(OnEventFn callback) {
      _on_singlestep = callback;
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

    OnEventFn _on_software_breakpoint;
    OnEventFn _on_singlestep;

  private:
    vm_event_request_t get_request();
    void put_response(vm_event_response_t rsp);
    void read_events();
  };
}

#endif //XENDBG_HVMMONITOR_HPP
