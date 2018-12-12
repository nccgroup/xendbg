//
// Created by Spencer Michaels on 9/28/18.
//

#include <GDBServer/GDBConnection.hpp>
#include <GDBServer/GDBServer.hpp>

using xd::gdb::GDBServer;

GDBServer::GDBServer(uvw::Loop &loop)
  : _server(loop.resource<uvw::TcpHandle>())
{
}

GDBServer::~GDBServer() {
  stop();
}

void GDBServer::stop() {
  if (!_server->closing())
    _server->close();
}

void GDBServer::listen(const std::string &address, uint16_t port, OnAcceptFn on_accept, OnErrorFn on_error) {
  _on_accept = std::move(on_accept);
  _on_error = std::move(on_error);

  _server->data(shared_from_this());

  _server->once<uvw::ErrorEvent>([](const auto &event, auto &tcp) {
    auto self = tcp.template data<GDBServer>();
    self->_on_error(event);
  });

  // Only accept one connection; LLDB doesn't handle multiple clients attached to she same stub
  _server->once<uvw::ListenEvent>([](const auto &event, auto &tcp) {
    auto self = tcp.template data<GDBServer>();
    auto client = tcp.loop().template resource<uvw::TcpHandle>();

    client->template on<uvw::CloseEvent>(
        [ptr = tcp.shared_from_this()](const auto&, auto&) { ptr->close(); });
    client->template on<uvw::EndEvent>(
        [](const auto&, auto &client) { client.close(); });

    tcp.accept(*client);

    self->_on_accept(*self, std::make_shared<GDBConnection>(client));
  });

  _server->bind(address, port);
  _server->listen();
}
