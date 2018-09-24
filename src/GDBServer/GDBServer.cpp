//
// Created by Spencer Michaels on 9/20/18.
//

#include <numeric>

#include "GDBServer.hpp"
#include "../uvcast.hpp"

using uvcast::uv_upcast;
using xd::gdbsrv::GDBConnection;
using xd::gdbsrv::GDBServer;
using xd::gdbsrv::pkt::GDBRequestPacket;
using xd::gdbsrv::pkt::GDBResponsePacket;
using xd::uv::OnErrorFn;
using xd::uv::UVTCP;

GDBServer::GDBServer(uv::UVLoop &loop)
    : _tcp(loop), _timer(loop)
{
};

void GDBServer::run(const std::string& address, uint16_t port,
    size_t max_connections, OnAcceptFn on_accept, OnErrorFn on_error)
{
  // Clean up expired connections
  // TODO: connections aren't running when first accepted and may get deleted
  /*
  _timer.start([this]() {
    _connections.erase(std::remove_if(
          _connections.begin(), _connections.end(),
          [](const auto &connection) {
            return !connection.is_running();
          }),
      _connections.end());
    return false;
  }, 100, 100);
  */

  _tcp.bind(address, port);
  _tcp.listen([this, on_accept, max_connections](auto &server) {
    /* Accept unconditionally. If connections are maxed out, we just let the
     * connection object go out of scope, which closes the corresponding TCP
     * stream. Otherwise, it gets moved into _connections.
     */
    auto connection = server.accept();
    if (_connections.size() < max_connections) {
      _connections.emplace_back(std::move(connection));
      on_accept(*this, _connections.back());
    }
  }, on_error);
}

void GDBServer::broadcast(const pkt::GDBResponsePacket &packet,
        uv::OnErrorFn on_error)
{
  for (auto &connection : _connections)
    connection.send(packet, on_error);
}
