//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBPACKETREADER_HPP
#define XENDBG_GDBPACKETREADER_HPP

#define PACKET_BUFFER_MAX_SIZE 0x400

#include <optional>
#include <queue>
#include <string>
#include <variant>

#include <netinet/in.h>

namespace xd::dbg::stub {

  struct Packet {};
  using GDBPacket = std::variant<Packet>;

  class GDBPacketReader {
  public:
    explicit GDBPacketReader(int remote_fd);
    GDBPacket read_and_parse_packet();

  private:
    struct RawGDBPacket {
      std::string contents;
      uint8_t checksum;
    };

    RawGDBPacket read_packet();
    GDBPacket parse_packet(const std::string &buffer);

  private:
    const int _remote_fd;

    std::queue<RawGDBPacket> _raw_packets;
    char _buffer[PACKET_BUFFER_MAX_SIZE];
    size_t _buffer_pos;
  };

}


#endif //XENDBG_GDBPACKETREADER_HPP
