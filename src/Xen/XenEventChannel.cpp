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
