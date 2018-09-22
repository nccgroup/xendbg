//
// Created by Spencer Michaels on 9/20/18.
//

#include <numeric>

#include "GDBServer.hpp"

using xd::gdbsrv::GDBConnection;
using xd::gdbsrv::GDBServer;
using xd::gdbsrv::pkt::GDBRequestPacket;
using xd::gdbsrv::pkt::GDBResponsePacket;

GDBServer::GDBServer(const uv::UVLoop &loop, const std::string& address_str, uint16_t port)
    : _loop(loop)
{
  _server = new uv_tcp_t;
  uv_tcp_init(_loop.get(), _server);
  _server->data = this;

  struct sockaddr_in address;
  uv_ip4_addr(address_str.c_str(), port, &address);

  uv_tcp_bind(_server, (const struct sockaddr *) &address, 0);
};

GDBServer::~GDBServer() {
  std::cout << "destroy" << std::endl;
  stop();
  free(_server);
}

void GDBServer::start(OnAcceptFn on_accept) {
  _on_accept = on_accept;

  if (uv_listen(uv_upcast<uv_stream_t>(_server), 10, GDBServer::on_connect) < 0)
    throw std::runtime_error("Listen failed!");

  std::cout << "Listening..." << std::endl;
}


void GDBServer::stop() {
  uv_close(uv_upcast<uv_handle_t>(_server), [](uv_handle_t *close_handle) {
    free(close_handle);
  });
}

void GDBServer::on_connect(uv_stream_t *server, int status) {
  std::cout << "Got connection." <<std::endl;

  if (status < 0)
    throw std::runtime_error("Listen failed!");

  const auto self = (GDBServer*)server->data;

  auto client = new uv_tcp_t;
  uv_tcp_init(self->_loop.get(), client);

  if (uv_accept(server, uv_upcast<uv_stream_t>(client))) {
    uv_close(uv_upcast<uv_handle_t>(client), [](uv_handle_t *close_handle) {
      free(close_handle);
    });
    throw std::runtime_error("Accept failed!");
  }

  std::cout << "Accepted." << std::endl;

  auto &connections = self->_connections;
  connections.emplace(connections.end(), uv_upcast<uv_stream_t>(client));
  self->_on_accept(connections.front());
};
