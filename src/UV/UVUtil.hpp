//
// Created by Spencer Michaels on 9/23/18.
//

#ifndef XENDBG_UVUTIL_HPP
#define XENDBG_UVUTIL_HPP

#include <memory>

#include <uv.h>

#include "../uvcast.hpp"

namespace xd::uv {

  template <typename Handle_t>
  static void close_and_free_handle(Handle_t *handle) {
    uv_close(uvcast::uv_upcast<uv_handle_t>(handle), [](uv_handle_t *handle) {
      free(handle);
    });
  }

  template <typename Handle_t>
  static void shutdown_close_and_free_stream_handle(Handle_t *handle) {
    auto req = new uv_shutdown_t;
    uv_shutdown(req, uvcast::uv_upcast<uv_stream_t>(handle), [](uv_shutdown_t *req, int status) {
      if (status < 0)
        throw std::runtime_error("Shutdown failed!");

      uv_close(uvcast::uv_upcast<uv_handle_t>(req->handle), [](uv_handle_t *close_handle) {
        free(close_handle);
      });
      free(req);
    });
  }

  template <typename Handle_t>
  using UVHandlePtr = std::unique_ptr<Handle_t, decltype(&close_and_free_handle<Handle_t>)>;

  template <typename Handle_t>
  using UVStreamHandlePtr = std::unique_ptr<Handle_t, 
        decltype(&shutdown_close_and_free_stream_handle<Handle_t>)>;

}

#endif //XENDBG_UVUTIL_HPP
