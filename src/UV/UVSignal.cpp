#include "../uvcast.hpp"

#include "UVLoop.hpp"
#include "UVSignal.hpp"

using uvcast::uv_upcast;
using xd::uv::close_and_free_handle;
using xd::uv::UVLoop;
using xd::uv::UVSignal;

UVSignal::UVSignal(UVLoop &loop)
  : _signal(new uv_signal_t, &close_and_free_handle), _is_running(false)
{
  uv_signal_init(loop.get(), _signal.get());
  _signal->data = this;
}

UVSignal::UVSignal(UVSignal&& other)
  : _signal(std::move(other._signal)),
    _on_signal(std::move(other._on_signal)),
    _is_running(other._is_running)
{
  if (_signal)
    _signal->data = this;
}

UVSignal& UVSignal::operator=(UVSignal&& other) {
  _signal = std::move(other._signal);
  if (_signal)
    _signal->data = this;
  _on_signal = std::move(other._on_signal);
  _is_running = other._is_running;
  return *this;
}

void UVSignal::start(OnSignalFn on_tick, int signum) {
  _is_running = true;
  _on_signal = std::move(on_tick);

  uv_signal_start(_signal.get(), [](uv_signal_t *signal, int /*signum*/) {
    auto self = (UVSignal*) signal->data;
    self->_on_signal();
  }, signum);
}

void UVSignal::stop() {
  uv_signal_stop(_signal.get());
  _is_running = false;
}
