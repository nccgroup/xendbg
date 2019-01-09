//
// Copyright (C) 2018-2019 Spencer Michaels
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
#include <Xen/XenEventChannel.hpp>
#include <Xen/XenException.hpp>

using xd::xen::XenEventChannel;

XenEventChannel::XenEventChannel()
  : _xenevtchn(xenevtchn_open(nullptr, 0), &xenevtchn_close)
{
}

int XenEventChannel::get_fd() {
  int ret = xenevtchn_fd(_xenevtchn.get());
  if (ret < 0)
    throw XenException("Failed to get event channel FD!", errno);
  return ret;
}

XenEventChannel::Port XenEventChannel::get_next_pending_channel() {
  int ret = xenevtchn_pending(_xenevtchn.get());
  if (ret < 0)
    throw XenException("Failed to get next pending event channel!", errno);
  return ret;
}

XenEventChannel::Port XenEventChannel::unmask_channel(Port port) {
  int ret = xenevtchn_unmask(_xenevtchn.get(), port);
  if (ret < 0)
    throw XenException("Failed to get next pending event channel!", errno);
  return ret;
}


XenEventChannel::Port XenEventChannel::bind_interdomain(
    const Domain &domain, Port remote_port)
{
  int ret = xenevtchn_bind_interdomain(_xenevtchn.get(), domain.get_domid(), remote_port);
  if (ret < 0)
    throw XenException("Failed to bind inter-domain!", errno);
  return ret;
}

void XenEventChannel::unbind(Port port) {
  int ret = xenevtchn_unbind(_xenevtchn.get(), port);
  if (ret < 0)
    throw XenException("Failed to unbind!", errno);
}

void XenEventChannel::notify(Port port) {
  xenevtchn_notify(_xenevtchn.get(), port);
}
