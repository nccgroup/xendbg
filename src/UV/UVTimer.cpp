#include <include/UV/UVCast.hpp>
#include <include/UV/UVLoop.hpp>
#include <include/UV/UVTimer.hpp>

using uvcast::uv_upcast;
using xd::uv::close_and_free_handle;
using xd::uv::UVLoop;
using xd::uv::UVTimer;

UVTimer::UVTimer(UVLoop &loop)
  : _timer(new uv_timer_t, &close_and_free_handle), _is_running(false)
{
  uv_timer_init(loop.get(), _timer.get());
  _timer->data = this;
}

UVTimer::UVTimer(UVTimer&& other)
  : _timer(std::move(other._timer)),
    _on_tick(std::move(other._on_tick)),
    _is_running(other._is_running)
{
  if (_timer)
    _timer->data = this;
}

UVTimer& UVTimer::operator=(UVTimer&& other) {
  _timer = std::move(other._timer);
  if (_timer)
    _timer->data = this;
  _on_tick = std::move(other._on_tick);
  _is_running = other._is_running;
  return *this;
}

void UVTimer::start(OnTickFn on_tick, uint64_t initial_delay, uint64_t interval) {
  _is_running = true;
  _on_tick = std::move(on_tick);

  uv_timer_start(_timer.get(), [](uv_timer_t *timer) {
    auto self = (UVTimer*) timer->data;
    if (self->_on_tick(*self))
      self->stop();
  }, initial_delay, interval);
}

void UVTimer::stop() {
  uv_timer_stop(_timer.get());
  _is_running = false;
}
