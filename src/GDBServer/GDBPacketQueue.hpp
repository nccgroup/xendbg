//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBPACKETQUEUE_HPP
#define XENDBG_GDBPACKETQUEUE_HPP

#include <optional>
#include <queue>
#include <string>
#include <vector>

namespace xd::gdbsrv {

  class GDBPacketQueue {
  public:
    void enqueue(std::vector<char> data);
    std::optional<std::string> dequeue();

  private:
    std::queue<std::string> _packets;
    std::vector<char> _buffer;
  };

}

#endif //XENDBG_GDBPACKETQUEUE_HPP
