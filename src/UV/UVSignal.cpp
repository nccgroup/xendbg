#include "../uvcast.hpp"

#include "UVLoop.hpp"
#include "UVSignal.hpp"

using uvcast::uv_upcast;
using xd::uv::UVLoop;
using xd::uv::UVSignal;

UVSignal::UVSignal(UVLoop &loop)
  : _is_running(false)
{
  uv_signal_init(loop.get(), &_signal);
  _signal.data = this;
}

UVSignal::~UVSignal() {
  uv_close(uv_upcast<uv_handle_t>(&_signal), [](uv_handle_t *) {
  });
}

void UVSignal::start(OnSignalFn on_tick, int signum) {
  _is_running = true;
  _on_signal = std::move(on_tick);

  uv_signal_start(&_signal, [](uv_signal_t *signal, int /*signum*/) {
    auto self = (UVSignal*) signal->data;
    self->_on_signal();
  }, signum);
}

void UVSignal::stop() {
  uv_signal_stop(&_signal);
  _is_running = false;
}
