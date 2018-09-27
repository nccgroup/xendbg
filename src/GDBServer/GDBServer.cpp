//
// Created by Spencer Michaels on 9/20/18.
//

#include <numeric>

#include <GDBServer/GDBServer.hpp>

using xd::gdbsrv::GDBConnection;
using xd::gdbsrv::GDBServer;
using xd::gdbsrv::pkt::GDBRequestPacket;
using xd::gdbsrv::pkt::GDBResponsePacket;

GDBServer::GDBServer(uvw::Loop &loop)
    : _tcp(loop.resource<uvw::TcpHandle>())
{
};

void GDBServer::run(const std::string& address, uint16_t port,
    size_t max_connections, OnAcceptFn on_accept, OnErrorFn on_error)
{
  _tcp->bind(address, port);
  _tcp->once<uvw::ListenEvent>([](const auto &event, auto &tcp) {
    auto client = tcp.loop().template resource<uvw::TcpHandle>();

  });

  _tcp->listen([this, on_accept, max_connections](auto &server) {
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
