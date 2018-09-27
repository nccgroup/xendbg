#include <UV/UVCast.hpp>

#include <UV/UVLoop.hpp>
#include <UV/UVIdle.hpp>

using uvcast::uv_upcast;
using xd::uv::close_and_free_handle;
using xd::uv::UVLoop;
using xd::uv::UVIdle;

UVIdle::UVIdle(UVLoop &loop)
  : _idle(new uv_idle_t, &close_and_free_handle), _is_running(false)
{
  uv_idle_init(loop.get(), _idle.get());
  _idle->data = this;
}

UVIdle::UVIdle(UVIdle&& other)
  : _idle(std::move(other._idle)),
    _on_tick(std::move(other._on_tick)),
    _is_running(other._is_running)
{
  if (_idle)
    _idle->data = this;
}

UVIdle& UVIdle::operator=(UVIdle&& other) {
  _idle = std::move(other._idle);
  if (_idle)
    _idle->data = this;
  _on_tick = std::move(other._on_tick);
  _is_running = other._is_running;
  return *this;
}

void UVIdle::start(OnTickFn on_tick) {
  _is_running = true;
  _on_tick = std::move(on_tick);

  _idle->data = this;
  uv_idle_start(_idle.get(), [](uv_idle_t *idle) {
    auto self = (UVIdle*) idle->data;
    self->_on_tick();
  });
}

void UVIdle::stop() {
  uv_idle_stop(_idle.get());
  _is_running = false;
}
