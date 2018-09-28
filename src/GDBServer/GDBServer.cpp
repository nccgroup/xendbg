//
// Created by Spencer Michaels on 9/28/18.
//

#include <GDBServer/GDBConnection.hpp>
#include <GDBServer/GDBServer.hpp>

using xd::gdbsrv::GDBServer;

GDBServer::GDBServer(uvw::Loop &loop)
  : _tcp(loop.resource<uvw::TcpHandle>())
{
}

void GDBServer::listen(const std::string &address, uint16_t port, OnAcceptFn on_accept, OnErrorFn on_error) {
  _tcp->once<uvw::ErrorEvent>([on_error](const auto &event, auto &tcp) {
    on_error(event);
  });

  // Only accept one connection; LLDB doesn't handle multiple clients attached to she same stub
  _tcp->once<uvw::ListenEvent>([on_accept](const auto &event, auto &tcp) {
    auto client = tcp.loop().template resource<uvw::TcpHandle>();

    client->on<uvw::CloseEvent>([ptr = tcp.shared_from_this()](const auto&, auto&) { ptr->close(); });
    client->on<uvw::EndEvent>([](const auto&, auto &client) { client.close(); });

    tcp.accept(*client);
    on_accept(GDBConnection(client));
  });

  _tcp->bind(address, port);
  _tcp->listen();
}
