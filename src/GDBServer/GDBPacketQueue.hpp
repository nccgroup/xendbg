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

  struct GDBPacket {
    std::string contents;
    uint8_t checksum;
  };

  class GDBPacketQueue {
  public:
    void enqueue(const std::vector<char> &data);
    std::optional<GDBPacket> dequeue();

  private:
    std::queue<GDBPacket> _packets;
    std::vector<char> _buffer;
  };

}

#endif //XENDBG_GDBPACKETQUEUE_HPP
