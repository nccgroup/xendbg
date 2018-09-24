//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_UVTCP_HPP
#define XENDBG_UVTCP_HPP

#include <iostream>
#include <functional>
#include <string>

#include <uv.h>

#include "UVUtil.hpp"

namespace xd::uv {

  using OnErrorFn = std::function<void(int)>;

  class UVLoop;
  class UVTCP;

  namespace {
    template <typename Data_t>
    struct WriteData {
      Data_t data;
      OnErrorFn on_error;
    };

    template <>
    struct WriteData<const char*> {
      std::string data;
      OnErrorFn on_error;
    };
  }

  class UVTCP {
  public:
    using OnConnectFn = std::function<void(UVTCP&)>;
    using OnReadFn = std::function<void(std::vector<char>)>;
    using OnCloseFn = std::function<void()>;

    UVTCP(UVLoop &loop);
    ~UVTCP() = default;

    UVTCP(UVTCP&& other);
    UVTCP& operator=(UVTCP&& other);

    UVTCP(const UVTCP& other) = delete;
    UVTCP& operator=(const UVTCP& other) = delete;

    uv_tcp_t *get() { return _tcp.get(); };

    bool is_reading() const { return _is_reading; };

    void bind(const std::string &address, uint16_t port);
    void listen(OnConnectFn on_connect, OnErrorFn on_error);
    UVTCP accept();

    void read_start(OnReadFn on_read, OnCloseFn on_close, OnErrorFn on_error);
    void read_stop();

    template <typename Data_t>
    void write(Data_t contents, OnErrorFn on_error) {
      const auto data = new WriteData<Data_t> {
        std::move(contents),
        std::move(on_error)
      };

      uv_buf_t buf;
      buf.base = data->data.data();
      buf.len = data->data.size();

      auto wreq = new uv_write_t;
      wreq->data = data;

      uv_write(wreq, uvcast::uv_upcast<uv_stream_t>(_tcp.get()), &buf, 1,
        [](uv_write_t *req, int status) {
          auto write_data = (WriteData<Data_t>*) req->data;

          if (status < 0)
            write_data->on_error(status);

          delete write_data;
          free(req);
        });
    }

  private:
    UVLoop &_loop;
    UVStreamHandlePtr<uv_tcp_t> _tcp;
    OnConnectFn _on_connect;
    OnReadFn _on_read;
    OnErrorFn _on_read_error, _on_listen_error;
    OnCloseFn _on_close;
    bool _is_reading;

    static void on_connect(uv_stream_t *server, int status);
    static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept;

  };
}

#endif //XENDBG_UVTCP_HPP
