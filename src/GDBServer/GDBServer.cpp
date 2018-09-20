//
// Created by Spencer Michaels on 9/20/18.
//

#include <iostream>

#include <uvcast.h>

#include "GDBServer.hpp"

using xd::gdbsrv::GDBServer;
using xd::gdbsrv::GDBPacketQueue;

GDBServer::GDBServer(std::string address, uint16_t port)
    : _address(std::move(address)), _port(port)
{};

GDBServer::~GDBServer() {
  stop();
}

void GDBServer::start(OnReceiveFn on_receive) {
  _on_receive = std::move(on_receive);

  uv_loop_init(&_loop);
  _loop.data = this;

  auto server = new uv_tcp_t;
  uv_tcp_init(&_loop, server);
  server->data = this;

  struct sockaddr_in address;
  uv_ip4_addr(_address.c_str(), _port, &address);

  uv_tcp_bind(server, (const struct sockaddr *) &address, 0);

  int err = uv_listen(uv_upcast<uv_stream_t>(server), 10,
      [](uv_stream_t *server, int status) {
        const auto self = (GDBServer*)server->data;

        if (status < 0)
          throw std::runtime_error("Listen failed!");

        auto client = new uv_tcp_t;
        uv_tcp_init(&self->_loop, client);
        client->data = self;

        if (uv_accept(server, uv_upcast<uv_stream_t>(client))) {
          std::cout << "Accept failed" << std::endl;
          uv_close(uv_upcast<uv_handle_t>(client), destroy_stream_context);
          return;
        }

        std::cout << "Accepted." << std::endl;
        self->_packet_queues[uv_upcast<uv_stream_t>(client)] = GDBPacketQueue();

        uv_read_start(uv_upcast<uv_stream_t>(client), alloc_buffer,
          [](uv_stream_t *sock, ssize_t nread, const uv_buf_t *buf) {
            const auto self = (GDBServer*)sock->data;

            if (nread <= 0) {
              if (nread != UV_EOF) {
                std::cout << "Read error!" << std::endl;
              }
              std::cout << "Got EOF." << std::endl;
              uv_close(uv_upcast<uv_handle_t>(sock), destroy_stream_context);
              free(buf->base);
            } else {
              std::cout << "Got data." << std::endl;
              auto data = std::vector<char>(buf->base, buf->base + nread);
              auto &queue = self->_packet_queues[uv_upcast<uv_stream_t>(sock)];

              queue.enqueue(data);
              free(buf->base);

              for (auto &pair : self->_packet_queues) {
                std::optional<std::string> packet;
                while ((packet = pair.second.dequeue()))
                  self->_on_receive(*packet);
              }
            }
          });
      });

  if (err < 0)
    throw std::runtime_error("Listen failed!");

  auto signal = new uv_signal_t;
  uv_signal_init(&_loop, signal);
  signal->data = this;

  uv_signal_start(signal, [](uv_signal_t *signal_handle, int signal) {
    const auto self = (GDBServer*) signal_handle->data;

    std::ignore = signal;
    auto idle = new uv_idle_t;
    uv_idle_init(&self->_loop, idle);
    idle->data = self;

    uv_idle_start(idle, [](uv_idle_t *handle) {
      const auto self = (GDBServer*) handle->data;

      uv_idle_stop(handle);
      uv_close(uv_upcast<uv_handle_t>(handle), [](uv_handle_t *close_handle) {
        free(close_handle);
      });
      uv_stop(&self->_loop);
    });

    uv_signal_stop(signal_handle);
    uv_close(uv_upcast<uv_handle_t>(signal_handle), [](uv_handle_t *close_handle) {
      free(close_handle);
    });
  }, SIGINT);

  std::cout << "Listening..." << std::endl;
  uv_run(&_loop, UV_RUN_DEFAULT);

  stop();
}

void GDBServer::stop() {
  uv_walk(&_loop, [](uv_handle_t *walk_handle, void *arg) {
    uv_close(walk_handle, [](uv_handle_t *close_handle) {
      free(close_handle);
    });
  }, nullptr);

  uv_run(&_loop, UV_RUN_DEFAULT);

  if (uv_loop_close(&_loop)) {
    throw std::runtime_error("Loop close failed!");
  }
}

void GDBServer::destroy_stream_context(uv_handle_t *handle) noexcept {
  if (handle) {
    const auto server = (GDBServer*)handle->data;

    uv_stream_t *stream = uv_downcast<uv_stream_t>(handle);
    const auto found = server->_packet_queues.find(stream);
    if (found != server->_packet_queues.end())
      server->_packet_queues.erase(found);

    free(handle);
  }
}

void GDBServer::alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept {
  std::ignore = h;
  buf->base = (char*) malloc(suggested);
  buf->len = suggested;
}
