//
// Created by Spencer Michaels on 9/20/18.
//

#ifndef XENDBG_GDBPACKETQUEUE_HPP
#define XENDBG_GDBPACKETQUEUE_HPP

#include <exception>
#include <optional>
#include <queue>
#include <string>

#include "GDBPacket.hpp"

namespace xd::gdb {

  class NoPacketException : std::exception {};

  class GDBPacketQueue {
  public:
    void append(const std::vector<char> &data);
    GDBPacket pop();

    bool empty() const { return _packets.empty(); };

  private:
    std::queue<GDBPacket> _packets;
    std::vector<char> _buffer;
  };

}

#endif //XENDBG_GDBPACKETQUEUE_HPP
