#include "../uvcast.hpp"

#include "UVLoop.hpp"
#include "UVTimer.hpp"

using uvcast::uv_upcast;
using xd::uv::UVLoop;
using xd::uv::UVTimer;

UVTimer::UVTimer(const UVLoop &loop)
  : _loop(loop), _timer(new uv_timer_t)
{
  uv_timer_init(loop.get(), _timer);
  _timer->data = this;
}

UVTimer::~UVTimer() {
  uv_close(uv_upcast<uv_handle_t>(_timer), [](uv_handle_t *close_handle) {
    free(close_handle);
  });
}

void UVTimer::start(OnTickFn on_tick, uint64_t interval, uint64_t initial_delay) {
  _on_tick = std::move(on_tick);

  uv_timer_start(_timer, [](uv_timer_t *timer) {
    auto self = (UVTimer*) timer->data;
    if (self->_on_tick()) {
      uv_timer_stop(timer);
    }
  }, initial_delay, interval);
}
