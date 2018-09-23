#include "../uvcast.hpp"

#include "UVLoop.hpp"
#include "UVTimer.hpp"

using uvcast::uv_upcast;
using xd::uv::UVLoop;
using xd::uv::UVTimer;

UVTimer::UVTimer(UVLoop &loop)
  : _is_running(false)
{
  uv_timer_init(loop.get(), &_timer);
  _timer.data = this;
}

UVTimer::~UVTimer() {
  uv_close(uv_upcast<uv_handle_t>(&_timer), [](uv_handle_t *) {
  });
}

void UVTimer::start(OnTickFn on_tick, uint64_t initial_delay, uint64_t interval) {
  _is_running = true;
  _on_tick = std::move(on_tick);

  uv_timer_start(&_timer, [](uv_timer_t *timer) {
    auto self = (UVTimer*) timer->data;
    if (self->_on_tick())
      self->stop();
  }, initial_delay, interval);
}

void UVTimer::stop() {
  uv_timer_stop(&_timer);
  _is_running = false;
}
