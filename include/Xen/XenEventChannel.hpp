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

    void notify(Port port);

  private:
    std::unique_ptr<xenevtchn_handle, decltype(&xenevtchn_close)> _xenevtchn;

  };
}

#endif //XENDBG_XENEVENTCHANNEL_HPP
