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

#ifndef XENDBG_XENCALL_HPP
#define XENDBG_XENCALL_HPP

#include <cstring>
#include <cstddef>
#include <functional>
#include <optional>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <type_traits>
#include <utility>

#include <errno.h>

#include "Common.hpp"
#include "XenException.hpp"

#include "BridgeHeaders/domctl.h"
#include "BridgeHeaders/xencall.h"

namespace xd::xen {

  class Domain;

  class XenCall {
  private:
    static xen_domctl _dummy_domctl;

  public:
    using DomctlUnion = decltype(XenCall::_dummy_domctl.u);
    using InitFn = std::function<void(DomctlUnion&)>;
    using CleanupFn = std::function<void()>;

    explicit XenCall(std::shared_ptr<xc_interface> xenctrl);

    DomctlUnion do_domctl(const Domain &domain, uint32_t command, InitFn init = {}, CleanupFn cleanup = {}) const;

  private:
    std::shared_ptr<xc_interface> _xenctrl;
    std::unique_ptr<xencall_handle, decltype(&xencall_close)> _xencall;
  };

}

#endif //XENDBG_XENCALL_HPP
