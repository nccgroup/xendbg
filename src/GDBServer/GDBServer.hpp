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

#include "GDBConnection.hpp"
#include "GDBResponsePacket.hpp"
#include "GDBRequestPacket.hpp"
#include "../UV/UVLoop.hpp"
#include "../UV/UVTimer.hpp"

namespace xd::gdbsrv {

  class GDBServer {
  public:
    using OnAcceptFn = std::function<void(GDBConnection&)>;

  public:
    GDBServer(uv::UVLoop &loop);

    GDBServer(GDBServer&& other);
    GDBServer& operator=(GDBServer&& other);

    GDBServer(const GDBServer& other) = delete;
    GDBServer& operator=(const GDBServer& other) = delete;

    void run(const std::string& address_str, uint16_t port, size_t max_connections,
        OnAcceptFn on_accept);

  private:
    static void close_server(uv_tcp_t *server);

    uv::UVLoop &_loop;
    uv::UVTimer _timer;
    std::unique_ptr<uv_tcp_t, decltype(&close_server)> _server;
    OnAcceptFn _on_accept;
    size_t _max_connections;

    std::vector<GDBConnection> _connections;

    static void on_connect(uv_stream_t *server, int status);
  };

}

#endif //XENDBG_GDBSERVER_HPP
