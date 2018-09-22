//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBSERVER_HPP
#define XENDBG_GDBSERVER_HPP

#include <cstdint>
#include <functional>
#include <queue>
#include <string>
#include <unordered_map>

#include <uv.h>
#include <uvcast.h>

#include "GDBConnection.hpp"
#include "GDBResponsePacket.hpp"
#include "GDBRequestPacket.hpp"
#include "UVLoop.hpp"

namespace xd::gdbsrv {

  class GDBServer {
  public:
    using OnAcceptFn = std::function<void(GDBConnection&)>;

  public:
    GDBServer(const uv::UVLoop &loop, const std::string& address_str, uint16_t port);
    ~GDBServer();

    GDBServer(GDBServer&& other) = default;
    GDBServer(const GDBServer& other) = delete;
    GDBServer& operator=(const GDBServer& other) = delete;

    void start(OnAcceptFn on_accept);
    void stop();

  private:
    const uv::UVLoop &_loop;
    uv_tcp_t *_server;
    OnAcceptFn _on_accept;

    std::vector<GDBConnection> _connections;

    static void on_connect(uv_stream_t *server, int status);
  };

}

#endif //XENDBG_GDBSERVER_HPP
