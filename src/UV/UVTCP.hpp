//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVTCP_HPP
#define XENDBG_UVTCP_HPP

#include <functional>
#include <string>

#include <uv.h>

#include "UVUtil.hpp"

namespace xd::uv {

  class UVLoop;

  class UVTCP {
  public:
    using OnConnectFn = std::function<void(UVTCP&)>;
    using OnReadFn = std::function<void(std::vector<char>)>;
    using OnErrorFn = std::function<void(int)>;
    using OnCloseFn = std::function<void()>;

    UVTCP(UVLoop &loop);
    ~UVTCP() = default;

    UVTCP(UVTCP&& other);
    UVTCP& operator=(UVTCP&& other);

    UVTCP(const UVTCP& other) = delete;
    UVTCP& operator=(const UVTCP& other) = delete;

    uv_tcp_t *get() { return _tcp.get(); };

    void bind(const std::string &address, uint16_t port);
    void listen(OnErrorFn on_error);
    UVTCP accept();

    void read_start(OnReadFn on_read, OnCloseFn on_close, OnErrorFn on_error);
    void read_stop();

  private:
    UVLoop &_loop;
    UVStreamHandlePtr<uv_tcp_t> _tcp;
    OnConnectFn _on_connect;
    OnReadFn _on_read;
    OnErrorFn _on_read_error, _on_listen_error;
    OnCloseFn _on_close;

    static void on_connect(uv_stream_t *server, int status);
    static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept;

  };
}

#endif //XENDBG_UVTCP_HPP
