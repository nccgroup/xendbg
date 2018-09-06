#include <iostream>
#include <numeric>
#include <string>

#include <unistd.h>

#include "GDBPacketReader.hpp"
#include "../Util/pop_ret.hpp"
#include "../Util/string.hpp"

#define PACKET_BUFFER_MAX_SIZE 0x400

using xd::dbg::stub::GDBPacket;
using xd::dbg::stub::GDBPacketReader;
using xd::util::pop_ret;

GDBPacketReader::GDBPacketReader(int remote_fd)
  : _remote_fd(remote_fd)
{
}

GDBPacket GDBPacketReader::read_and_parse_packet() {
  const auto packet = read_packet();
  const auto sum = std::accumulate(packet.contents.begin(), packet.contents.end(),
      (uint8_t)0);

  if (sum != packet.checksum) {
    write(_remote_fd, "-", 1); // ACK: checksum error
  } else {
    write(_remote_fd, "+", 1); // ACK: OK
  }

  return Packet{};
  //return parse_packet(packet.contents);
}

GDBPacketReader::RawGDBPacket GDBPacketReader::read_packet() {
  char buffer[PACKET_BUFFER_MAX_SIZE];
  char *buffer_ptr = buffer;
  size_t remaining_space = sizeof(buffer);

  while (_raw_packets.empty()) {
    const auto bytes_read = read(_remote_fd, buffer_ptr, remaining_space);
    if (bytes_read < 0)
      throw std::runtime_error("Failed to read remote FD!");

    _raw_packet_buffer.append(std::string(buffer_ptr, bytes_read));

    buffer_ptr += bytes_read;
    remaining_space -= bytes_read;
    if (remaining_space == 0)
      throw std::runtime_error("Packet too long!");

    auto start = _raw_packet_buffer.find('$');
    auto end = _raw_packet_buffer.find('\0', start+1);
    while (start != std::string::npos && end != std::string::npos) {
      auto csum_start = _raw_packet_buffer.find('#', start);
      if (csum_start != end-3)
        throw std::runtime_error("Malformed packet: missing checksum delimiter!");

      const auto checksum_str = _raw_packet_buffer.substr(csum_start+1, 2);
      const auto checksum = (uint8_t)std::stoul(checksum_str, 0, 16);

      const auto content = _raw_packet_buffer.substr(start+1, csum_start-start-1);

      _raw_packets.push(RawGDBPacket{
        content,
        checksum
      });

      std::cout << "content: " << content << std::endl;
      std::cout << "checksum: " << checksum << std::endl;

      start = _raw_packet_buffer.find('$', end);
      end = _raw_packet_buffer.find('\0', start);
    }

    if (start != std::string::npos)
      _raw_packet_buffer = _raw_packet_buffer.substr(start);
    else
      _raw_packet_buffer.clear();
  }

  const auto packet = _raw_packets.front();
  _raw_packets.pop();

  return packet;
}

GDBPacket GDBPacketReader::parse_packet(const std::string &buffer)
{
  size_t buffer_pos = 0;

  switch (buffer_pos++) {
    // TODO
  }

  throw std::runtime_error("Unknown packet type!");
}
