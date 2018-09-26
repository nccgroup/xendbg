#include <sys/mman.h>

#include <Xen/Domain.hpp>
#include <Xen/HVMMonitor.hpp>

using xd::uv::UVLoop;
using xd::uv::UVPoll;
using xd::xen::Domain;
using xd::xen::monitor::HVMMonitor;

HVMMonitor::HVMMonitor(UVLoop &loop, XenHandlePtr xen, const Domain &domain)
  : _xen(std::move(xen)), _domain(domain), _ring_page(nullptr, unmap_ring_page),
    _poll(loop, _xen->get_event_channel().get_fd())
{
  auto [ring_page, evtchn_port] = _domain.enable_monitor();

  _ring_page.reset(ring_page);
  _port = _xen->get_event_channel().bind_interdomain(_domain, evtchn_port);

  SHARED_RING_INIT((vm_event_sring_t*)ring_page);
  BACK_RING_INIT(&_back_ring, (vm_event_sring_t*)ring_page, XC_PAGE_SIZE);

  _domain.monitor_software_breakpoint(true);
  _domain.monitor_debug_exceptions(true, true);
  _domain.monitor_cpuid(true);
  _domain.monitor_descriptor_access(true);
  _domain.monitor_privileged_call(true);
}

HVMMonitor::~HVMMonitor() {
  _xen->get_event_channel().unbind(_port);
}

void HVMMonitor::start(OnEventFn on_event) {
  // TODO: this capture fails if moved
  _poll.start([this, on_event](const auto &fd_event) {
      if (!fd_event.readable)
        read_events(on_event);
  });
}

void HVMMonitor::stop() {
  _poll.stop();
}

vm_event_request_t HVMMonitor::get_request() {
    vm_event_request_t req;
    RING_IDX req_cons;

    req_cons = _back_ring.req_cons;

    /* Copy request */
    memcpy(&req, RING_GET_REQUEST(&_back_ring, req_cons), sizeof(req));
    req_cons++;

    /* Update ring */
    _back_ring.req_cons = req_cons;
    _back_ring.sring->req_event = req_cons + 1;

    return req;
}

void HVMMonitor::put_response(vm_event_response_t rsp) {
    RING_IDX rsp_prod;

    rsp_prod = _back_ring.rsp_prod_pvt;

    /* Copy response */
    memcpy(RING_GET_RESPONSE(&_back_ring, rsp_prod), &rsp, sizeof(rsp));
    rsp_prod++;

    /* Update ring */
    _back_ring.rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(&_back_ring);
}

void HVMMonitor::read_events(OnEventFn on_event) {
  while (RING_HAS_UNCONSUMED_REQUESTS(&_back_ring)) {
    auto req = get_request();

    vm_event_response_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.version = VM_EVENT_INTERFACE_VERSION;
    rsp.vcpu_id = req.vcpu_id;
    rsp.flags = (req.flags & VM_EVENT_FLAG_VCPU_PAUSED);
    rsp.reason = req.reason;

    if (req.version != VM_EVENT_INTERFACE_VERSION)
      continue; // TODO: error

    switch (req.reason) {
      case VM_EVENT_REASON_MEM_ACCESS:
        break;
      case VM_EVENT_REASON_SOFTWARE_BREAKPOINT:
        break;
      case VM_EVENT_REASON_PRIVILEGED_CALL:
        break;
      case VM_EVENT_REASON_SINGLESTEP:
        break;
      case VM_EVENT_REASON_DEBUG_EXCEPTION:
        break;
      case VM_EVENT_REASON_CPUID:
        break;
      case VM_EVENT_REASON_DESCRIPTOR_ACCESS:
        break;
    }

    put_response(rsp);
  }
}

void HVMMonitor::unmap_ring_page(void *ring_page) {
if (ring_page)
  munmap(ring_page, XC_PAGE_SIZE);
}
