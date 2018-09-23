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
  using UVHandlePtr = std::unique_ptr<Handle_t, decltype(&close_and_free_handle<Handle_t>)>;

}

#endif //XENDBG_UVUTIL_HPP
