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

namespace xd::dbg::stub {

  class GDBStub {
  public:
    void run(int port, in_addr_t addr = INADDR_LOOPBACK);

  private:
    int tcp_socket_open(in_addr_t addr, int port);
    int tcp_socket_accept(int sock_fd);

    void reply(const std::string &buffer);
    void reply_error(uint8_t err);
    void reply_ok();
    void reply_not_supported();

  private:
    int _remote_fd;
  };

}


#endif //XENDBG_GDBSTUB_HPP
