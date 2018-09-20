#include <iostream>
#include <optional>
#include <string>
#include <queue>
#include <unordered_map>
#include <vector>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <uv.h>

#include "third_party/sunrise/uvcast.h"

class PacketQueue {
public:
  void enqueue(std::vector<char> data) {
    _buffer.insert(_buffer.end(), data.begin(), data.end());

    auto start = _buffer.begin();
    while (start != _buffer.end()) {
      auto packet_start = std::find(start, _buffer.end(), '$');
      auto chksum_start = std::find(packet_start, _buffer.end(), '#');

      if (packet_start == _buffer.end() ||
          chksum_start == _buffer.end() ||
          _buffer.end() - chksum_start < 4)
        break;

      _packets.push(std::string(packet_start, chksum_start+4));
      start = chksum_start + 4;
    }

    start = std::find(start, _buffer.end(), '$');
    _buffer.erase(_buffer.begin(), start);
  }

  std::optional<std::string> dequeue() {
    if (_packets.empty())
      return std::nullopt;

    const auto packet = _packets.front();
    _packets.pop();
    return packet;
  }

private:
  std::queue<std::string> _packets;
  std::vector<char> _buffer;
};

class Server {
public:
  Server(std::string address, uint16_t port)
    : _address(std::move(address)), _port(port)
  {}

  void start() {
    uv_loop_init(&_s_loop);

    auto server = new uv_tcp_t;
    uv_tcp_init(&_s_loop, server);

    struct sockaddr_in address;
    uv_ip4_addr(_address.c_str(), _port, &address);

    uv_tcp_bind(server, (const struct sockaddr*)&address, 0);

    int err = uv_listen(uv_upcast<uv_stream_t>(server), 10,
      [](uv_stream_t *server, int status) {
        if (status < 0)
          return; // TODO: error

        auto client = new uv_tcp_t;
        uv_tcp_init(&_s_loop, client);

        if (uv_accept(server, uv_upcast<uv_stream_t>(client))) {
          std::cout << "Accept failed" << std::endl;
          uv_close(uv_upcast<uv_handle_t>(client), destroy_stream_context);
          return;
        }

        std::cout << "Accepted." << std::endl;
        _s_packet_queues[uv_upcast<uv_stream_t>(client)] = PacketQueue();

        uv_read_start(uv_upcast<uv_stream_t>(client), alloc_buffer,
          [](uv_stream_t* sock, ssize_t nread, const uv_buf_t *buf) {
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
              auto &queue = _s_packet_queues[uv_upcast<uv_stream_t>(sock)];

              queue.enqueue(data);
              free(buf->base);

              for (auto &pair : _s_packet_queues) {
                std::optional<std::string> packet;
                while ((packet = pair.second.dequeue()))
                  std::cout << "RECV: " << *packet << std::endl;
              }
            }
          });


      });

    if (err < 0)
      return; // TODO: error

    std::cout << "Listening..." << std::endl;
    uv_run(&_s_loop, UV_RUN_DEFAULT);

    uv_walk(&_s_loop, [](uv_handle_t *walk_handle, void *arg) {
      uv_close(walk_handle, [](uv_handle_t *close_handle) {
        free(close_handle);
      });
    }, nullptr);
    uv_run(&_s_loop, UV_RUN_DEFAULT);

    if (uv_loop_close(&_s_loop))
      std::cout << "Failed to close" << std::endl;
  }

private:
  static void destroy_stream_context(uv_handle_t *handle) noexcept {
    if (handle) {
      uv_stream_t* stream = uv_downcast<uv_stream_t>(handle);
      {
        const auto found = _s_context.find(stream);
        if (found != _s_context.end()) {
          if (found->second != nullptr) {
            free(found->second);
          }
          _s_context.erase(found);
        }
      }
      {
        const auto found = _s_packet_queues.find(stream);
        if (found != _s_packet_queues.end())
          _s_packet_queues.erase(found);
      }
    }
    free(handle);
  }

  static void alloc_buffer(uv_handle_t *h, size_t suggested, uv_buf_t *buf) noexcept {
    std::ignore = h;
    buf->base = (char*) malloc(suggested);
    buf->len = suggested;
  }

private:
  std::string _address;
  uint16_t _port;

  static uv_loop_t _s_loop;
  static std::unordered_map<uv_stream_t*, void*> _s_context;
  static std::unordered_map<uv_stream_t*, PacketQueue> _s_packet_queues;
};

uv_loop_t Server::_s_loop;
std::unordered_map<uv_stream_t*, void*> Server::_s_context;
std::unordered_map<uv_stream_t*, PacketQueue> Server::_s_packet_queues;

int main() {
  Server server("127.0.0.1", 1234);
  server.start();
}
