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

#ifndef XENDBG_XENCTRL_HPP
#define XENDBG_XENCTRL_HPP

#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sys/ioctl.h>

#include <Registers/RegistersX86Any.hpp>

#include "BridgeHeaders/xenctrl.h"
#include "BridgeHeaders/xenguest.h"
#include "Common.hpp"
#include "XenCall.hpp"
#include "XenEventChannel.hpp"

namespace xd::xen {

  class Domain;

  class XenCtrl {
  private:
    struct XenVersion {
      int major, minor;
    };
    static xen_domctl _dummy_domctl;

  public:
    using DomctlUnion = decltype(XenCtrl::_dummy_domctl.u);
    using InitFn = std::function<void(DomctlUnion&)>;
    using CleanupFn = std::function<void()>;

    XenCtrl();

    xc_interface *get() const { return _xenctrl.get(); };
    XenVersion get_xen_version() const;

    DomInfo get_domain_info(DomID domid) const;

  private:
    std::shared_ptr<xc_interface> _xenctrl;

  public:
    XenCall xencall;
  };

}

#endif //XENDBG_XENCTRL_HPP
