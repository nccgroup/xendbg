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
    void append(const std::vector<char> &data);
    GDBPacket pop();

    bool empty() const { return _packets.empty(); };

  private:
    std::queue<GDBPacket> _packets;
    std::vector<char> _buffer;
  };

}

#endif //XENDBG_GDBPACKETQUEUE_HPP
