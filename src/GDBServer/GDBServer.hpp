//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBSERVER_HPP
#define XENDBG_GDBSERVER_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

#include <uv.h>

#include "GDBPacketQueue.hpp"

namespace xd::gdbsrv {

  class GDBServer {
  private:
    using OnReceiveFn = std::function<void(std::string)>;
  public:
    GDBServer(std::string address, uint16_t port);
    ~GDBServer();

    void start(OnReceiveFn on_receive);
    void stop();

  private:
    static void destroy_stream_context(uv_handle_t *handle) noexcept;
    static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept;

  private:
    std::string _address;
    uint16_t _port;
    OnReceiveFn _on_receive;
    bool _is_running;

    uv_loop_t _loop;
    std::unordered_map<uv_stream_t*, GDBPacketQueue> _packet_queues;
  };

}

#endif //XENDBG_GDBSERVER_HPP
