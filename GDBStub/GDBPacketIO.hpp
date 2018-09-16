//
// Created by Spencer Michaels on 9/5/18.
//

#ifndef XENDBG_GDBPACKETIO_HPP
#define XENDBG_GDBPACKETIO_HPP

#define PACKET_BUFFER_MAX_SIZE 0x400

#include <memory>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <variant>

#include <netinet/in.h>

#include "GDBRequestPacket.hpp"
#include "GDBResponsePacket.hpp"

namespace xd::dbg::gdbstub {

  class UnknownPacketTypeException : public std::runtime_error {
  public:
    UnknownPacketTypeException(const std::string &data)
      : std::runtime_error(data) {};
  };

  class GDBPacketIO {
  public:
    explicit GDBPacketIO(int remote_fd);

    pkt::GDBRequestPacket read_packet();
    void write_packet(const pkt::GDBResponsePacket& packet);
    void set_ack_enabled(bool enabled) { _ack_enabled = enabled; };

  private:
    using RawGDBPacket = std::string;

    RawGDBPacket read_raw_packet();
    void write_raw_packet(const RawGDBPacket& raw_packet);

    pkt::GDBRequestPacket parse_raw_packet(const RawGDBPacket &raw_packet);

  private:
    using Buffer = std::vector<char>;
      
    const int _remote_fd;
    bool _ack_enabled;
    std::queue<RawGDBPacket> _raw_packets;
    Buffer _buffer;
  };

}


#endif //XENDBG_GDBPACKETIO_HPP
