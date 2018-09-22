#include <stdlib.h>

#include "UVLoop.hpp"
#include "../uvcast.hpp"

using uvcast::uv_upcast;
using xd::uv::UVLoop;

UVLoop::UVLoop() {
  _loop = new uv_loop_t;
  uv_loop_init(_loop);

  // Listen for ctrl-C
  auto signal = new uv_signal_t;
  uv_signal_init(_loop, signal);
  signal->data = this;

  uv_signal_start(signal, UVLoop::on_sigint, SIGINT);
}

UVLoop::~UVLoop() {
  uv_loop_close(_loop);
  free(_loop);
}

void UVLoop::run() const {
  uv_run(_loop, UV_RUN_DEFAULT);
}

void UVLoop::on_sigint(uv_signal_t *signal_handle, int /*signal*/) {
  const auto self = (UVLoop*) signal_handle->data;

  auto idle = new uv_idle_t;
  uv_idle_init(self->get(), idle);
  idle->data = self;

  uv_idle_start(idle, [](uv_idle_t *handle) {
    const auto self = (UVLoop*) handle->data;

    uv_idle_stop(handle);
    uv_close(uv_upcast<uv_handle_t>(handle), [](uv_handle_t *close_handle) {
      free(close_handle);
    });
    uv_stop(self->get());
  });

  uv_signal_stop(signal_handle);
  uv_close(uv_upcast<uv_handle_t>(signal_handle), [](uv_handle_t *close_handle) {
    free(close_handle);
  });
}
