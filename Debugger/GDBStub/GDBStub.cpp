//
// Created by Spencer Michaels on 9/5/18.
//

#include <stdexcept>
#include <sstream>

#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <numeric>
#include <signal.h>
#include <unistd.h>

#include "GDBPacket.hpp"
#include "GDBPacketIO.hpp"
#include "GDBStub.hpp"
#include "../../Util/overloaded.hpp"

using xd::dbg::gdbstub::GDBPacketIO;
using xd::dbg::gdbstub::GDBStub;
using xd::util::overloaded;

int tcp_socket_open(in_addr_t addr, int port);
int tcp_socket_accept(int sock_fd);
int receive_packet(void *buffer);

GDBStub::GDBStub(int port)
  : _address(INADDR_LOOPBACK), _port(port)
{
}

GDBStub::GDBStub(in_addr_t address, int port)
  : _address(address), _port(port)
{
}

void GDBStub::run() {
  int listen_fd = tcp_socket_open(_address, _port);
  int remote_fd = tcp_socket_accept(listen_fd);

  GDBPacketIO io(remote_fd);

  bool running = true;
  while (running) {
    try {
      const auto packet = io.read_packet();
    } catch (const std::runtime_error &e) {
    }
  }
}

int GDBStub::tcp_socket_open(in_addr_t addr, int port) {
  int sock_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (sock_fd < 0)
    throw std::runtime_error("Failed to open socket!");

  socklen_t tmp;
  setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, sizeof(tmp));

  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = PF_INET;
  sockaddr.sin_port = htons(port);
  sockaddr.sin_addr.s_addr = htonl(addr);

  if (bind(sock_fd, (struct sockaddr*)&sockaddr, sizeof(sockaddr))) {
    close(sock_fd);
    throw std::runtime_error("Failed to bind socket!");
  }
  if (listen(sock_fd, 1)) {
    close(sock_fd);
    throw std::runtime_error("Failed to listen on socket!");
  }

  return sock_fd;
}


int GDBStub::tcp_socket_accept(int sock_fd) {
  if (sock_fd < 0)
    throw std::runtime_error("Invalid socket FD!");

  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));

  socklen_t tmp;
  int remote_fd = accept(sock_fd, (struct sockaddr*)&sockaddr, &tmp);
  if (remote_fd < 0) {
    close(sock_fd);
    throw std::runtime_error("Failed to accept!");
  }

  // Instruct TCP not to delay small packets. This improves interactivity.
  tmp = 1;
  setsockopt(remote_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&tmp, sizeof(tmp));
  close(sock_fd);

  // Don't exit automatically when the remote side does
  signal(SIGPIPE, SIG_IGN);

  return remote_fd;
}
