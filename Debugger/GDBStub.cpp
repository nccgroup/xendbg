//
// Created by Spencer Michaels on 9/5/18.
//

#include <stdexcept>

#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "GDBStub.hpp"

using xd::debugger::GDBStub;

int tcp_socket_open(in_addr_t addr, int port);
int tcp_socket_accept(int sock_fd);
bool receive_and_process_packet(int remote_fd);

void xd::debugger::GDBStub::run(int port) {
  int listen_fd = tcp_socket_open(INADDR_LOOPBACK, port);
  int remote_fd = tcp_socket_accept(listen_fd);

  while (receive_and_process_packet(remote_fd));
}

int tcp_socket_open(in_addr_t addr, int port) {
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


int tcp_socket_accept(int sock_fd) {
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

bool receive_and_process_packet(int remote_fd) {

}
