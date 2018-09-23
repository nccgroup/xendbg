#include "../uvcast.hpp"

#include "UVLoop.hpp"
#include "UVPoll.hpp"

using uvcast::uv_upcast;
using xd::uv::close_and_free_handle;
using xd::uv::UVLoop;
using xd::uv::UVPoll;

UVPoll::UVPoll(UVLoop &loop, int fd)
  : _poll(new uv_poll_t, &close_and_free_handle), _is_running(false)
{
  uv_poll_init(loop.get(), _poll.get(), fd);
  _poll->data = this;
}

UVPoll::UVPoll(UVPoll&& other)
  : _poll(std::move(other._poll)),
    _on_event(std::move(other._on_event)),
    _is_running(other._is_running)
{
  if (_poll)
    _poll->data = this;
}

UVPoll& UVPoll::operator=(UVPoll&& other) {
  _poll = std::move(other._poll);
  if (_poll)
    _poll->data = this;
  _on_event = std::move(other._on_event);
  _is_running = other._is_running;
  return *this;
}

void UVPoll::start(OnEventFn on_event) {
  _is_running = true;
  _on_event = std::move(on_event);

  uv_poll_start(_poll.get(), UV_READABLE, [](uv_poll_t *poll, int status, int events) {
    if (status < 0)
      throw std::runtime_error("Failed to poll!"); // TODO

    if (events) {
      auto self = (UVPoll*) poll->data;

      Event event {
        (bool)(events & UV_READABLE),
        (bool)(events & UV_WRITABLE),
        (bool)(events & UV_DISCONNECT),
        (bool)(events & UV_PRIORITIZED)
      };

      self->_on_event(event);
    }
  });
}

void UVPoll::stop() {
  uv_poll_stop(_poll.get());
  _is_running = false;
}
