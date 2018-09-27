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

#include <uvw.hpp>

#include "GDBConnection.hpp"
#include "GDBResponsePacket.hpp"
#include "GDBRequestPacket.hpp"

namespace xd::gdbsrv {

  class GDBServer : std::enable_shared_from_this<GDBServer> {
  public:
    using OnAcceptFn = std::function<void(GDBServer&, GDBConnection&)>;

  public:
    explicit GDBServer(uvw::Loop &loop);

    void run(const std::string& address, uint16_t port, size_t max_connections,
        OnAcceptFn on_accept, uv::OnErrorFn on_error);

    void broadcast(const pkt::GDBResponsePacket &packet,
        uv::OnErrorFn on_error);

  private:
    std::shared_ptr<uvw::TcpHandle> _tcp;
  };

}

#endif //XENDBG_GDBSERVER_HPP
