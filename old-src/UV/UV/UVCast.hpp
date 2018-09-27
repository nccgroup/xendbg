#ifndef XENDBG_UVCAST_HPP
#define XENDBG_UVCAST_HPP

/**
 * Original UVCast implementation by Jeff Dileo. TOOD: repo URL
 */

#include <uv.h>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

namespace uvcast {

  static const std::unordered_map<
    uv_handle_type,
    std::unordered_set<uv_handle_type>
  > handle_downcast_map = {
    {UV_ASYNC, {UV_HANDLE}},
    {UV_CHECK, {UV_HANDLE}},
    {UV_FS_EVENT, {UV_HANDLE}},
    {UV_FS_POLL, {UV_HANDLE}},
    {UV_IDLE, {UV_HANDLE}},
    {UV_POLL, {UV_HANDLE}},
    {UV_PREPARE, {UV_HANDLE}},
    {UV_PROCESS, {UV_HANDLE}},
    {UV_UDP, {UV_HANDLE}},
    {UV_TIMER, {UV_HANDLE}},
    {UV_SIGNAL, {UV_HANDLE}},
    {UV_STREAM, {UV_HANDLE}},
    {UV_TCP, {UV_HANDLE, UV_STREAM}},
    {UV_NAMED_PIPE, {UV_HANDLE, UV_STREAM}},
    {UV_TTY, {UV_HANDLE, UV_STREAM}}
  };

  struct UVHandle {
    typedef uv_handle_t type;
    static constexpr uv_handle_type handle_type = UV_HANDLE;
  };

  struct UVAsync : UVHandle {
    typedef uv_async_t type;
    static constexpr uv_handle_type handle_type = UV_ASYNC;
  };
  struct UVCheck : UVHandle {
    typedef uv_check_t type;
    static constexpr uv_handle_type handle_type = UV_CHECK;
  };
  struct UVFsEvent : UVHandle {
    typedef uv_fs_event_t type;
    static constexpr uv_handle_type handle_type = UV_FS_EVENT;
  };
  struct UVFsPoll : UVHandle {
    typedef uv_fs_poll_t type;
    static constexpr uv_handle_type handle_type = UV_FS_POLL;
  };
  struct UVIdle : UVHandle {
    typedef uv_idle_t type;
    static constexpr uv_handle_type handle_type = UV_IDLE;
  };
  struct UVPoll : UVHandle {
    typedef uv_poll_t type;
    static constexpr uv_handle_type handle_type = UV_POLL;
  };
  struct UVPrepare : UVHandle {
    typedef uv_prepare_t type;
    static constexpr uv_handle_type handle_type = UV_PREPARE;
  };
  struct UVProcess : UVHandle {
    typedef uv_process_t type;
    static constexpr uv_handle_type handle_type = UV_PROCESS;
  };
  struct UVUdp : UVHandle {
    typedef uv_udp_t type;
    static constexpr uv_handle_type handle_type = UV_UDP;
  };
  struct UVTimer : UVHandle {
    typedef uv_timer_t type;
    static constexpr uv_handle_type handle_type = UV_TIMER;
  };
  struct UVSignal : UVHandle {
    typedef uv_signal_t type;
    static constexpr uv_handle_type handle_type = UV_SIGNAL;
  };

  struct UVStream : UVHandle {
    typedef uv_stream_t type;
    static constexpr uv_handle_type handle_type = UV_STREAM;
  };
  struct UVTcp : UVStream {
    typedef uv_tcp_t type;
    static constexpr uv_handle_type handle_type = UV_TCP;
  };
  struct UVPipe : UVStream {
    typedef uv_pipe_t type;
    static constexpr uv_handle_type handle_type = UV_NAMED_PIPE;
  };
  struct UVTty : UVStream {
    typedef uv_tty_t type;
    static constexpr uv_handle_type handle_type = UV_TTY;
  };


  struct UVReq {
    typedef uv_req_t type;
    static constexpr uv_req_type req_type = UV_REQ;
  };

  struct UVConnect : UVReq {
    typedef uv_connect_t type;
    static constexpr uv_req_type req_type = UV_CONNECT;
  };
  struct UVWrite : UVReq {
    typedef uv_write_t type;
    static constexpr uv_req_type req_type = UV_WRITE;
  };
  struct UVShutdown : UVReq {
    typedef uv_shutdown_t type;
    static constexpr uv_req_type req_type = UV_SHUTDOWN;
  };
  struct UVUdpSend : UVReq {
    typedef uv_udp_send_t type;
    static constexpr uv_req_type req_type = UV_UDP_SEND;
  };
  struct UVFs : UVReq {
    typedef uv_fs_t type;
    static constexpr uv_req_type req_type = UV_FS;
  };
  struct UVWork : UVReq {
    typedef uv_work_t type;
    static constexpr uv_req_type req_type = UV_WORK;
  };
  struct UVGetaddrinfo : UVReq {
    typedef uv_getaddrinfo_t type;
    static constexpr uv_req_type req_type = UV_GETADDRINFO;
  };
  struct UVGetnameinfo : UVReq {
    typedef uv_getnameinfo_t type;
    static constexpr uv_req_type req_type = UV_GETNAMEINFO;
  };

  template<typename T>
  struct get_UV_type {
    typedef std::nullptr_t type;
  };

#define make_get_UV_type(TYPE) template<>\
  struct get_UV_type<TYPE::type> {\
    typedef TYPE type;\
  }

  make_get_UV_type(UVHandle);
  make_get_UV_type(UVAsync);
  make_get_UV_type(UVCheck);
  make_get_UV_type(UVFsEvent);
  make_get_UV_type(UVFsPoll);
  make_get_UV_type(UVIdle);
  make_get_UV_type(UVPoll);
  make_get_UV_type(UVPrepare);
  make_get_UV_type(UVProcess);
  make_get_UV_type(UVUdp);
  make_get_UV_type(UVTimer);
  make_get_UV_type(UVSignal);
  make_get_UV_type(UVStream);
  make_get_UV_type(UVTcp);
  make_get_UV_type(UVPipe);
  make_get_UV_type(UVTty);
  make_get_UV_type(UVReq);
  make_get_UV_type(UVConnect);
  make_get_UV_type(UVWrite);
  make_get_UV_type(UVShutdown);
  make_get_UV_type(UVUdpSend);
  make_get_UV_type(UVFs);
  make_get_UV_type(UVWork);
  make_get_UV_type(UVGetaddrinfo);
  make_get_UV_type(UVGetnameinfo);

  template<typename To>
  struct get_uv_type {
    static_assert(std::is_base_of<UVHandle, To>::value
                  || std::is_base_of<UVReq, To>::value,
                  "bad type");
    typedef typename To::type type;
  };

  template <typename To, typename From>
  struct is_uv_upcast_safe {
    static_assert(
      !std::is_same<
        std::nullptr_t, typename get_UV_type<To>::type
      >::value,
      "invalid type"
    );
    static constexpr bool value =
      std::is_base_of<
        typename get_UV_type<To>::type,
        typename get_UV_type<From>::type
      >::value;
  };

  template<typename To, typename From>
  constexpr To* uv_upcast(From* from) {
    static_assert(is_uv_upcast_safe<To,From>::value, "incompatible types");
    return reinterpret_cast<To*>(from);
  };

  template<typename To, typename From>
  std::enable_if_t<
    is_uv_upcast_safe<uv_handle_t,From>::value
    && is_uv_upcast_safe<uv_handle_t, To>::value,
    To*
  >
  uv_downcast(From* from) {
    uv_handle_t* handle = uv_upcast<uv_handle_t>(from);
    uv_handle_type from_type = handle->type;
    uv_handle_type to_type = get_UV_type<To>::type::handle_type;
    if (from_type == to_type) {
      return reinterpret_cast<To*>(from);
    }
    auto const found = handle_downcast_map.find(from_type);
    if (found != handle_downcast_map.end()) {
      auto const& to_set = found->second;
      if (to_set.find(to_type) != to_set.end()) {
        return reinterpret_cast<To*>(from);
      }
    }
    return nullptr;
  };

  template<typename To, typename From>
  std::enable_if_t<
    is_uv_upcast_safe<uv_req_t,From>::value
    && is_uv_upcast_safe<uv_req_t, To>::value,
    To*
  >
  uv_downcast(From* from) {
    uv_req_t* req = uv_upcast<uv_req_t>(from);
    uv_req_type from_type = req->type;
    uv_req_type to_type = get_UV_type<To>::type::req_type;
    if (from_type == to_type) {
      return reinterpret_cast<To*>(from);
    }
    return nullptr;
  };


  template<typename To, typename From>
  std::enable_if_t<
    !is_uv_upcast_safe<uv_handle_t,From>::value
    && !is_uv_upcast_safe<uv_handle_t, To>::value
    && !is_uv_upcast_safe<uv_req_t,From>::value
    && !is_uv_upcast_safe<uv_req_t, To>::value,
    To*
  >
  uv_downcast(From*) {
    static_assert(!is_uv_upcast_safe<uv_handle_t,From>::value
                  && !is_uv_upcast_safe<uv_handle_t, To>::value
                  && !is_uv_upcast_safe<uv_req_t,From>::value
                  && !is_uv_upcast_safe<uv_req_t, To>::value,
                  "incompatible types");
    return nullptr;
  };

}

#endif //XENDBG_UVCAST_HPP
