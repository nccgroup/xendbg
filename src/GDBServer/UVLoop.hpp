//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVLOOP_HPP
#define XENDBG_UVLOOP_HPP

#include <stdlib.h>
#include <tuple>

#include <uv.h>
#include <uvcast.h>

namespace xd::uv {

  class UVLoop {
  public:
    UVLoop() {
      _loop = new uv_loop_t;
      uv_loop_init(_loop);

      // Listen for ctrl-C
      auto signal = new uv_signal_t;
      uv_signal_init(_loop, signal);
      signal->data = this;

      uv_signal_start(signal, UVLoop::on_sigint, SIGINT);
    }

    ~UVLoop() {
      uv_loop_close(_loop);
      free(_loop);

      /*
      // Close and free any remaining handles
      // TODO: this crashes if .run() was never called
      uv_walk(_loop, [](uv_handle_t *walk_handle, void *arg) {
        uv_close(walk_handle, [](uv_handle_t *close_handle) {
          free(close_handle);
        });
      }, nullptr);
      uv_run(_loop, UV_RUN_DEFAULT);
      */
    }

    uv_loop_t *get() const { return _loop; };

    void run() const {
      uv_run(_loop, UV_RUN_DEFAULT);
    }

  private:
    uv_loop_t *_loop;

    static void on_sigint(uv_signal_t *signal_handle, int /*signal*/) {
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
  };

}

#endif //XENDBG_UVLOOP_HPP
