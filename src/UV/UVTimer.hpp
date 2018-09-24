//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVTIMER_HPP
#define XENDBG_UVTIMER_HPP

#include <functional>

#include <uv.h>

#include "UVUtil.hpp"

namespace xd::uv {

  class UVLoop;

  class UVTimer {
  public:
    using OnTickFn = std::function<bool()>;

    UVTimer(UVLoop &loop);
    ~UVTimer() = default;

    UVTimer(UVTimer&& other);
    UVTimer& operator=(UVTimer&& other);

    UVTimer(const UVTimer& other) = delete;
    UVTimer& operator=(const UVTimer& other) = delete;

    void *data;

    uv_timer_t *get() { return _timer.get(); };
    bool is_running() const { return _is_running; };

    void start(OnTickFn on_tick, uint64_t initial_delay, uint64_t interval);
    void stop();

  private:
    UVHandlePtr<uv_timer_t> _timer;
    OnTickFn _on_tick;
    bool _is_running;
  };
}

#endif //XENDBG_UVTIMER_HPP
