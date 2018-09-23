//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVIDLE_HPP
#define XENDBG_UVIDLE_HPP

#include <functional>

#include <uv.h>

namespace xd::uv {

  class UVLoop;

  class UVIdle {
  public:
    using OnTickFn = std::function<void()>;

    UVIdle(UVLoop &loop);
    ~UVIdle();

    UVIdle(UVIdle&& other) = default;
    UVIdle(const UVIdle& other) = delete;
    UVIdle& operator=(UVIdle&& other) = default;
    UVIdle& operator=(const UVIdle& other) = delete;

    uv_idle_t *get() { return &_idle; };
    bool is_running() const { return _is_running; };

    void start(OnTickFn on_tick);
    void stop();

  private:
    uv_idle_t _idle;
    OnTickFn _on_tick;
    bool _is_running;
  };
}

#endif //XENDBG_UVIDLE_HPP
