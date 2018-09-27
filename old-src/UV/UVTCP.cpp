#include <iostream>
#include <vector>

#include <UV/UVLoop.hpp>
#include <UV/UVTCP.hpp>
#include <UV/UVCast.hpp>

using uvcast::uv_upcast;
using xd::uv::close_and_free_handle;
using xd::uv::UVLoop;
using xd::uv::UVTCP;

UVTCP::UVTCP(UVLoop &loop)
  : _loop(loop), _tcp(new uv_tcp_t, &close_and_free_handle)
{
  uv_tcp_init(loop.get(), _tcp.get());
  _tcp->data = this;
}

UVTCP::UVTCP(UVTCP&& other)
  : _loop(other._loop),
    _tcp(std::move(other._tcp)),
    _on_connect(std::move(other._on_connect)),
    _on_read(std::move(other._on_read)),
    _on_read_error(std::move(other._on_read_error)),
    _on_listen_error(std::move(other._on_listen_error)),
    _on_close(std::move(other._on_close))
{
  if (_tcp)
    _tcp->data = this;
}

UVTCP& UVTCP::operator=(UVTCP&& other) {
  _loop = std::move(other._loop);
  _tcp = std::move(other._tcp);
  if (_tcp)
    _tcp->data = this;
  _on_connect = std::move(other._on_connect);
  _on_read = std::move(other._on_read);
  _on_read_error = std::move(other._on_read_error);
  _on_listen_error = std::move(other._on_listen_error);
  _on_close = std::move(other._on_close);
  return *this;
}

void UVTCP::bind(const std::string &address, uint16_t port) {
  // TODO: errors
  struct sockaddr_in address_ip4;
  uv_ip4_addr(address.c_str(), port, &address_ip4);
  uv_tcp_bind(_tcp.get(), (const struct sockaddr *) &address_ip4, 0);
}

void UVTCP::listen(OnConnectFn on_connect, OnErrorFn on_error) {
  _on_connect = on_connect;
  _on_listen_error = on_error;

  if (uv_listen(uv_upcast<uv_stream_t>(_tcp.get()), 10, UVTCP::on_connect) < 0)
    throw std::runtime_error("Listen failed!)");
}

UVTCP UVTCP::accept() {
  UVTCP connection(_loop);
  if (uv_accept(uv_upcast<uv_stream_t>(_tcp.get()),
                uv_upcast<uv_stream_t>(connection.get())) < 0)
  {
    throw std::runtime_error("Accept failed!");
  }

  return connection;
}

void UVTCP::read_start(OnReadFn on_read, OnCloseFn on_close, OnErrorFn on_error) {
  _is_reading = true;

  _on_read = std::move(on_read);
  _on_close = std::move(on_close);
  _on_read_error = std::move(on_error);

  uv_read_start(uv_upcast<uv_stream_t>(_tcp.get()), UVTCP::alloc_buffer,
    [](uv_stream_t *sock, ssize_t nread, const uv_buf_t *buf) {
      const auto self = (UVTCP*)sock->data;
      if (nread <= 0) {
        self->_on_close();
        if (nread != UV_EOF)
          self->_on_read_error(nread);
      } else {
        auto data = std::vector<char>(buf->base, buf->base + nread);
        self->_on_read(*self, std::move(data));
      }

      free(buf->base);
    });
}

void UVTCP::read_stop() {
  uv_read_stop(uv_upcast<uv_stream_t>(_tcp.get()));
  _is_reading = false;
}

void UVTCP::on_connect(uv_stream_t *server, int status) {
  const auto self = (UVTCP*)server->data;

  if (status < 0)
    self->_on_listen_error(status);
  else
    self->_on_connect(*self);
};

void UVTCP::alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept {
  std::ignore = h;
  buf->base = (char*) malloc(suggested);
  buf->len = suggested;
}
