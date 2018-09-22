//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVLOOP_HPP
#define XENDBG_UVLOOP_HPP

#include <uv.h>

namespace xd::uv {

  class UVLoop {
  public:
    UVLoop();
    ~UVLoop();

    UVLoop(UVLoop&& other) = default;
    UVLoop(const UVLoop& other) = delete;
    UVLoop& operator=(UVLoop&& other) = default;
    UVLoop& operator=(const UVLoop& other) = delete;

    uv_loop_t *get() const { return _loop; };

    void run() const;

  private:
    uv_loop_t *_loop;

    static void on_sigint(uv_signal_t *signal_handle, int /*signal*/);

  };
}

#endif //XENDBG_UVLOOP_HPP
