//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVPOLL_HPP
#define XENDBG_UVPOLL_HPP

#include <functional>

#include <uv.h>

namespace xd::uv {

  class UVLoop;

  class UVPoll {
  private:
    struct Event {
      bool readable, writable, disconnect, prioritized;
    };

  public:
    using OnEventFn = std::function<void(const Event&)>;

    UVPoll(UVLoop &loop, int fd);
    ~UVPoll();

    UVPoll(UVPoll&& other) = default;
    UVPoll(const UVPoll& other) = delete;
    UVPoll& operator=(UVPoll&& other) = default;
    UVPoll& operator=(const UVPoll& other) = delete;

    uv_poll_t *get() { return &_poll; };
    bool is_running() const { return _is_running; };

    void start(OnEventFn on_event);
    void stop();

  private:
    uv_poll_t _poll;
    OnEventFn _on_event;
    bool _is_running;
  };
}

#endif //XENDBG_UVPOLL_HPP
