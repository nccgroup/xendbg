//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVTIMER_HPP
#define XENDBG_UVTIMER_HPP

#include <functional>

#include <uv.h>

namespace xd::uv {

  class UVLoop;

  class UVTimer {
  public:
    using OnTickFn = std::function<bool()>;

    UVTimer(UVLoop &loop);
    ~UVTimer();

    UVTimer(UVTimer&& other) = default;
    UVTimer(const UVTimer& other) = delete;
    UVTimer& operator=(UVTimer&& other) = default;
    UVTimer& operator=(const UVTimer& other) = delete;

    uv_timer_t *get() { return &_timer; };
    bool is_running() const { return _is_running; };

    void start(OnTickFn on_tick, uint64_t initial_delay, uint64_t interval);
    void stop();

  private:
    uv_timer_t _timer;
    OnTickFn _on_tick;
    bool _is_running;
  };
}

#endif //XENDBG_UVTIMER_HPP
