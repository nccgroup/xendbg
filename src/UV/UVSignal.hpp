//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVSIGNAL_HPP
#define XENDBG_UVSIGNAL_HPP

#include <functional>

#include <uv.h>

namespace xd::uv {

  class UVLoop;

  class UVSignal {
  public:
    using OnSignalFn = std::function<void()>;

    UVSignal(UVLoop &loop);
    ~UVSignal();

    UVSignal(UVSignal&& other) = default;
    UVSignal(const UVSignal& other) = delete;
    UVSignal& operator=(UVSignal&& other) = default;
    UVSignal& operator=(const UVSignal& other) = delete;

    uv_signal_t *get() { return &_signal; };
    bool is_running() const { return _is_running; };

    void start(OnSignalFn on_tick, int signum);
    void stop();

  private:
    uv_signal_t _signal;
    OnSignalFn _on_signal;
    bool _is_running;
  };
}

#endif //XENDBG_UVSIGNAL_HPP
