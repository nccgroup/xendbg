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

#ifndef XENDBG_COMMON_HPP
#define XENDBG_COMMON_HPP

#include <cstdint>
#include <functional>
#include <memory>

#include "BridgeHeaders/xenctrl.h"
#include "BridgeHeaders/xenguest.h"

namespace xd::xen {
  using Address = uintptr_t;
  using DomID = domid_t;
  using DomInfo = xc_dominfo_t;
  using MemInfo = std::unique_ptr<xc_domain_meminfo, std::function<void(xc_domain_meminfo *p)>>;
  using VCPU_ID = uint32_t;
  using WordSize = unsigned int;

}

#endif //XENDBG_COMMON_HPP
