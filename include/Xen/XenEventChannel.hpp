//
// Created by Spencer Michaels on 8/13/18.
//

#ifndef XENDBG_XENEVENTCHANNEL_HPP
#define XENDBG_XENEVENTCHANNEL_HPP

#include <memory>

#include "BridgeHeaders/xenevtchn.h"

namespace xd::xen {

  class Domain;

  class XenEventChannel {
  public:
    using Port = uint32_t;
    struct RingPageAndPort {
      void *ring_page;
      Port port;
    };

    XenEventChannel();

    xenevtchn_handle *get() const { return _xenevtchn.get(); };
    int get_fd();

    Port get_next_pending_channel();
    Port unmask_channel(Port port);

    Port bind_interdomain(const Domain &domain, Port remote_port);
    void unbind(Port port);

  private:
    std::unique_ptr<xenevtchn_handle, decltype(&xenevtchn_close)> _xenevtchn;

  };
}

#endif //XENDBG_XENEVENTCHANNEL_HPP
