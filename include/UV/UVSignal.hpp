//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVSIGNAL_HPP
#define XENDBG_UVSIGNAL_HPP

#include <functional>

#include <uv.h>

#include "UVUtil.hpp"

namespace xd::uv {

  class UVLoop;

  class UVSignal {
  public:
    using OnSignalFn = std::function<void()>;

    UVSignal(UVLoop &loop);
    ~UVSignal() = default;

    UVSignal(UVSignal&& other);
    UVSignal& operator=(UVSignal&& other);

    UVSignal(const UVSignal& other) = delete;
    UVSignal& operator=(const UVSignal& other) = delete;

    void *data;

    uv_signal_t *get() { return _signal.get(); };
    bool is_running() const { return _is_running; };

    void start(OnSignalFn on_tick, int signum);
    void stop();

  private:
    UVHandlePtr<uv_signal_t> _signal;
    OnSignalFn _on_signal;
    bool _is_running;
  };
}

#endif //XENDBG_UVSIGNAL_HPP
