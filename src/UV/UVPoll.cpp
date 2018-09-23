#include "../uvcast.hpp"

#include "UVLoop.hpp"
#include "UVPoll.hpp"

using uvcast::uv_upcast;
using xd::uv::UVLoop;
using xd::uv::UVPoll;

UVPoll::UVPoll(UVLoop &loop, int fd)
  : _is_running(false)
{
  uv_poll_init(loop.get(), &_poll, fd);
  _poll.data = this;
}

UVPoll::~UVPoll() {
  uv_close(uv_upcast<uv_handle_t>(&_poll), [](uv_handle_t *) {
  });
}

void UVPoll::start(OnEventFn on_event) {
  _is_running = true;
  _on_event = std::move(on_event);

  uv_poll_start(&_poll, UV_READABLE, [](uv_poll_t *poll, int status, int events) {
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
  uv_poll_stop(&_poll);
  _is_running = false;
}
