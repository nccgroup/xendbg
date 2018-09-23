//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVLOOP_HPP
#define XENDBG_UVLOOP_HPP

#include <memory>

#include <uv.h>

namespace xd::uv {

  class UVLoop {
  public:
    UVLoop();
    ~UVLoop() = default;

    UVLoop(UVLoop&& other);
    UVLoop& operator=(UVLoop&& other);

    UVLoop(const UVLoop& other) = delete;
    UVLoop& operator=(const UVLoop& other) = delete;

    uv_loop_t *get() { return _loop.get(); };

    void start();
    void stop();

  private:
    std::unique_ptr<uv_loop_t, decltype(&uv_loop_close)> _loop;
  };

}

#endif //XENDBG_UVLOOP_HPP
