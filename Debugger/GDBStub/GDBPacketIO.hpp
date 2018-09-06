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

namespace xd::dbg::gdbstub {

  namespace pkt {
    class GDBPacket;
  }

  class GDBPacketIO {
  public:
    explicit GDBPacketIO(int remote_fd);

    std::unique_ptr<pkt::GDBPacket> read_packet();
    void write_packet(std::unique_ptr<pkt::GDBPacket> packet);

  private:
    using RawGDBPacket = std::string;

    RawGDBPacket read_raw_packet();
    void write_raw_packet(RawGDBPacket raw_packet);

    std::unique_ptr<pkt::GDBPacket> parse_packet(const RawGDBPacket &buffer);

  private:
    const int _remote_fd;

    std::queue<RawGDBPacket> _raw_packets;
    std::string _raw_packet_buffer;
  };

}


#endif //XENDBG_GDBPACKETIO_HPP
