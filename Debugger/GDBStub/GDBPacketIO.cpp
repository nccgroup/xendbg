#include <iostream>
#include <numeric>
#include <sstream>
#include <string>

#include <unistd.h>

#include "GDBPacket.hpp"
#include "GDBPacketIO.hpp"
#include "../../Util/pop_ret.hpp"
#include "../../Util/string.hpp"

#define PACKET_BUFFER_MAX_SIZE 0x400

using xd::dbg::gdbstub::GDBPacketIO;
using xd::dbg::gdbstub::pkt::GDBPacket;
using xd::util::pop_ret;

using namespace xd::dbg::gdbstub::pkt;

GDBPacketIO::GDBPacketIO(int remote_fd)
  : _remote_fd(remote_fd)
{
}

std::unique_ptr<GDBPacket> GDBPacketIO::read_packet() {
  const auto raw_packet = read_raw_packet();
  return std::make_unique<NotSupported>();
}

void GDBPacketIO::write_packet(std::unique_ptr<GDBPacket> packet) {
  const auto raw_packet = packet->to_string();
  write_raw_packet(raw_packet);
}

GDBPacketIO::RawGDBPacket GDBPacketIO::read_raw_packet() {
  char buffer[PACKET_BUFFER_MAX_SIZE];
  char *buffer_ptr = buffer;
  size_t remaining_space = sizeof(buffer);

  while (_raw_packets.empty()) {
    const auto bytes_read = read(_remote_fd, buffer_ptr, remaining_space);

    // TODO: if == 0 then remote has closed, do something
    if (bytes_read < 0)
      throw std::runtime_error("Failed to read from remote FD!");

    buffer_ptr += bytes_read;
    remaining_space -= bytes_read;

    if (remaining_space == 0)
      throw std::runtime_error("Packet too long!");

    _raw_packet_buffer.append(std::string(buffer_ptr, bytes_read));

    auto start = _raw_packet_buffer.find('$');
    auto end = _raw_packet_buffer.find('\0', start+1);
    while (start != std::string::npos && end != std::string::npos) {
      auto csum_start = _raw_packet_buffer.find('#', start);
      if (csum_start != end-3)
        throw std::runtime_error("Malformed packet: missing checksum delimiter!");

      const auto contents = _raw_packet_buffer.substr(start+1, csum_start-start-1);
      const auto checksum_str = _raw_packet_buffer.substr(csum_start+1, 2);
      const auto checksum = (uint8_t)std::stoul(checksum_str, 0, 16);

      const auto checksum_calculated = std::accumulate(
          contents.begin(), contents.end(), (uint8_t)0);

      // If the checksums match, ACK the packet and record its contents
      // Otherwise, drop it and notify GDB of the failure
      if (checksum_calculated == checksum) {
        write(_remote_fd, "+", 1); // ACK

        _raw_packets.push(RawGDBPacket{contents});
      } else {
        write(_remote_fd, "-", 1); // Notify GDB of checksum error
      }

      start = _raw_packet_buffer.find('$', end);
      end = _raw_packet_buffer.find('\0', start);
    }

    // Remove read data from the temp buffer
    // If a packet is half-arrived, preserve its data for later
    if (start != std::string::npos)
      _raw_packet_buffer = _raw_packet_buffer.substr(start);
    else
      _raw_packet_buffer.clear();
  }

  const auto packet = _raw_packets.front();
  _raw_packets.pop();

  return packet;
}

void GDBPacketIO::write_raw_packet(RawGDBPacket raw_packet) {
  const auto checksum = std::accumulate(raw_packet.begin(), raw_packet.end(), (uint8_t)0);

  std::stringstream ss;
  ss << "$" << raw_packet << "#";
  ss << std::hex << checksum << "\0";
  const auto ss_str = ss.str();

  const auto data = ss_str.c_str();
  auto remaining = ss_str.size();

  auto data_ptr = data;
  while (remaining) {
    // TODO: if == 0 then remote has closed, do something
    auto bytes_written = write(_remote_fd, data_ptr, remaining);

    if (bytes_written < 0)
      throw std::runtime_error("Failed to write to remote FD!");

    data_ptr += bytes_written;
    remaining -= bytes_written;
  }
}

std::unique_ptr<GDBPacket> GDBPacketIO::parse_packet(const RawGDBPacket &buffer)
{
  size_t buffer_pos = 0;

  switch (buffer_pos++) {
    // TODO
  }

  throw std::runtime_error("Unknown packet type!");
}
