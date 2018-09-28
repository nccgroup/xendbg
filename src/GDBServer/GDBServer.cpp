//
// Created by Spencer Michaels on 9/28/18.
//

#include <GDBServer/GDBConnection.hpp>
#include <GDBServer/GDBServer.hpp>

using xd::gdbsrv::GDBServer;

GDBServer::GDBServer(uvw::Loop &loop)
  : _server(loop.resource<uvw::TcpHandle>())
{
}

void GDBServer::listen(const std::string &address, uint16_t port, OnAcceptFn on_accept, OnErrorFn on_error) {
  _server->data(shared_from_this());

  _server->once<uvw::ErrorEvent>([on_error](const auto &event, auto &tcp) {
    on_error(event);
  });

  // Only accept one connection; LLDB doesn't handle multiple clients attached to she same stub
  _server->once<uvw::ListenEvent>([on_accept](const auto &event, auto &tcp) {
    auto self = tcp.template data<GDBServer>();
    auto client = tcp.loop().template resource<uvw::TcpHandle>();

    client->template on<uvw::CloseEvent>(
        [ptr = tcp.shared_from_this()](const auto&, auto&) { ptr->close(); });
    client->template on<uvw::EndEvent>(
        [](const auto&, auto &client) { client.close(); });

    tcp.accept(*client);

    on_accept(*self, std::make_shared<GDBConnection>(client));
  });

  _server->bind(address, port);
  _server->listen();
}
