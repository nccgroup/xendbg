//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVIDLE_HPP
#define XENDBG_UVIDLE_HPP

#include <functional>
#include <memory>

#include <uv.h>

#include "UVUtil.hpp"

namespace xd::uv {

  class UVLoop;

  class UVIdle {
  public:
    using OnTickFn = std::function<void()>;

    UVIdle(UVLoop &loop);
    ~UVIdle() = default;

    UVIdle(UVIdle&& other);
    UVIdle& operator=(UVIdle&& other);

    UVIdle(const UVIdle& other) = delete;
    UVIdle& operator=(const UVIdle& other) = delete;

    uv_idle_t *get() { return _idle.get(); };
    bool is_running() const { return _is_running; };

    void start(OnTickFn on_tick);
    void stop();

  private:
    UVHandlePtr<uv_idle_t> _idle;
    OnTickFn _on_tick;
    bool _is_running;
  };
}

#endif //XENDBG_UVIDLE_HPP
