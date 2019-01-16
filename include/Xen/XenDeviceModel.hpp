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

#ifndef XENDBG_XENDEVICEMODEL_HPP
#define XENDBG_XENDEVICEMODEL_HPP

#include "BridgeHeaders/xendevicemodel.h"
#include "Common.hpp"

namespace xd::xen {

  class Domain;

  class XenDeviceModel {
  public:
    XenDeviceModel();

    xendevicemodel_handle *get() { return _xendevicemodel.get(); };

    void inject_event(const Domain &domain, VCPU_ID vcpu_id, uint8_t vector,
        uint8_t type, uint32_t error_code, uint8_t insn_len, uint64_t cr2);

  private:
    std::unique_ptr<xendevicemodel_handle,
      decltype(&xendevicemodel_close)> _xendevicemodel;

  };

}

#endif //XENDBG_XENDEVICEMODEL_HPP
