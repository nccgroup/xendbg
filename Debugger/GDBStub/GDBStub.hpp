//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBSTUB_HPP
#define XENDBG_GDBSTUB_HPP

#include <cstddef>
#include <string>
#include <queue>
#include <variant>

#include <netinet/in.h>

namespace xd::dbg::gdbstub {

  class GDBStub {
  public:
    GDBStub(int port);
    GDBStub(in_addr_t address, int port);

    void run();

  private:
    int tcp_socket_open(in_addr_t addr, int port);
    int tcp_socket_accept(int sock_fd);

  private:
    in_addr_t _address;
    int _port;
  };

}


#endif //XENDBG_GDBSTUB_HPP
