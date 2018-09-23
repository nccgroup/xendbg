#include "../uvcast.hpp"

#include "UVLoop.hpp"
#include "UVIdle.hpp"

using uvcast::uv_upcast;
using xd::uv::UVLoop;
using xd::uv::UVIdle;

UVIdle::UVIdle(UVLoop &loop)
  : _is_running(false)
{
  uv_idle_init(loop.get(), &_idle);
  _idle.data = this;
}

UVIdle::~UVIdle() {
  uv_close(uv_upcast<uv_handle_t>(&_idle), [](uv_handle_t *) {
  });
}

void UVIdle::start(OnTickFn on_tick) {
  _is_running = true;
  _on_tick = std::move(on_tick);

  uv_idle_start(&_idle, [](uv_idle_t *idle) {
    auto self = (UVIdle*) idle->data;
    self->_on_tick();
  });
}

void UVIdle::stop() {
  uv_idle_stop(&_idle);
  _is_running = false;
}
