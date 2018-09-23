//
// Created by Spencer Michaels on 9/20/18.
//

#include <numeric>

#include "GDBServer.hpp"
#include "../UV/UVUtil.hpp"
#include "../uvcast.hpp"

using uvcast::uv_upcast;
using xd::gdbsrv::GDBConnection;
using xd::gdbsrv::GDBServer;
using xd::gdbsrv::pkt::GDBRequestPacket;
using xd::gdbsrv::pkt::GDBResponsePacket;
using xd::uv::close_and_free_handle;

GDBServer::GDBServer(uv::UVLoop &loop)
    : _loop(loop), _timer(loop), _server(new uv_tcp_t, &close_server)
{
  uv_tcp_init(_loop.get(), _server.get());
  _server->data = this; // TODO: move constructor must update this
};

GDBServer::GDBServer(GDBServer&& other)
  : _loop(other._loop),
    _timer(std::move(other._timer)),
    _server(std::move(other._server)),
    _on_accept(std::move(other._on_accept)),
    _max_connections(other._max_connections),
    _connections(std::move(other._connections))
{
  if (_server)
    _server->data = this;
}

GDBServer& GDBServer::operator=(GDBServer&& other) {
  _loop = std::move(other._loop);
  _timer = std::move(other._timer);
  _server = std::move(other._server);
  if (_server)
    _server->data = this;
  _on_accept = std::move(other._on_accept);
  _max_connections = other._max_connections;
  _connections = std::move(other._connections);
  return *this;
}

void GDBServer::run(const std::string& address_str, uint16_t port, size_t max_connections,
    OnAcceptFn on_accept)
{
  _on_accept = std::move(on_accept);
  _max_connections = max_connections;

  // Clean up expired connections
  _timer.start([this]() {
    _connections.erase(std::remove_if(
          _connections.begin(), _connections.end(),
          [](const auto &connection) {
            return !connection.is_running();
          }),
      _connections.end());
    std::cout << _connections.size() << std::endl;
    return false;
  }, 100, 100);

  struct sockaddr_in address;
  uv_ip4_addr(address_str.c_str(), port, &address);

  uv_tcp_bind(_server.get(), (const struct sockaddr *) &address, 0);

  if (uv_listen(uv_upcast<uv_stream_t>(_server.get()), 10, GDBServer::on_connect) < 0)
    throw std::runtime_error(std::strerror(errno));
}

void GDBServer::on_connect(uv_stream_t *server, int status) {
  if (status < 0)
    throw std::runtime_error("Listen failed!");

  const auto self = (GDBServer*)server->data;

  auto client = new uv_tcp_t;
  uv_tcp_init(self->_loop.get(), client);

  if (self->_connections.size() >= self->_max_connections) {
    close_and_free_handle(client); // Reject
    return;
  } else if (uv_accept(server, uv_upcast<uv_stream_t>(client))) {
    close_and_free_handle(client);
    throw std::runtime_error("Accept failed!");
  }

  auto &connections = self->_connections;
  connections.emplace_back(self->_loop, uv_upcast<uv_stream_t>(client));
  self->_on_accept(connections.back());
};

void GDBServer::close_server(uv_tcp_t *server) {
  auto req = new uv_shutdown_t;
  uv_shutdown(req, uv_upcast<uv_stream_t>(server), [](uv_shutdown_t *req, int status) {
    if (status < 0)
      throw std::runtime_error("Shutdown failed!");

    uv_close(uv_upcast<uv_handle_t>(req->handle), [](uv_handle_t *close_handle) {
      free(close_handle);
    });
    free(req);
  });
}
