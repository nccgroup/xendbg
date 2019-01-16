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

#include <Xen/Domain.hpp>
#include <Xen/XenDeviceModel.hpp>
#include <Xen/XenException.hpp>

using xd::xen::Domain;
using xd::xen::VCPU_ID;
using xd::xen::XenDeviceModel;
using xd::xen::XenException;

XenDeviceModel::XenDeviceModel()
  : _xendevicemodel(xendevicemodel_open(nullptr, 0), xendevicemodel_close)
{
}

void XenDeviceModel::inject_event(const Domain &domain, VCPU_ID vcpu_id,
    uint8_t vector, uint8_t type, uint32_t error_code, uint8_t insn_len, uint64_t cr2)
{
  int err = xendevicemodel_inject_event(
      _xendevicemodel.get(), domain.get_domid(), vcpu_id,
      vector, type, error_code, insn_len, cr2);

  if (err < 0)
    throw XenException("Failed to inject event!");
}
