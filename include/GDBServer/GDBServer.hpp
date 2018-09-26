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
#include "../UV/UVTCP.hpp"
#include "../UV/UVTimer.hpp"

namespace xd::gdbsrv {

  class GDBServer {
  public:
    using OnAcceptFn = std::function<void(GDBServer&, GDBConnection&)>;

  public:
    GDBServer(uv::UVLoop &loop);

    GDBServer(GDBServer&& other);
    GDBServer& operator=(GDBServer&& other);

    GDBServer(const GDBServer& other) = delete;
    GDBServer& operator=(const GDBServer& other) = delete;

    void run(const std::string& address, uint16_t port, size_t max_connections,
        OnAcceptFn on_accept, uv::OnErrorFn on_error);

    void broadcast(const pkt::GDBResponsePacket &packet,
        uv::OnErrorFn on_error);

  private:
    uv::UVTCP _tcp;
    uv::UVTimer _timer;

    std::vector<GDBConnection> _connections;
  };

}

#endif //XENDBG_GDBSERVER_HPP
