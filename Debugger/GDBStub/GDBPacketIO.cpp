#include <iostream>
#include <numeric>
#include <sstream>
#include <string>

#include <unistd.h>

#include "GDBPacketIO.hpp"
#include "GDBResponsePacket.hpp"
#include "GDBRequestPacket.hpp"
#include "../../Util/pop_ret.hpp"
#include "../../Util/string.hpp"

#define PACKET_BUFFER_MAX_SIZE 0x400

using xd::dbg::gdbstub::GDBPacketIO;
using xd::dbg::gdbstub::pkt::GDBResponsePacket;
using xd::dbg::gdbstub::pkt::GDBRequestPacket;
using xd::util::pop_ret;

GDBPacketIO::GDBPacketIO(int remote_fd)
  : _remote_fd(remote_fd)
{
}

GDBRequestPacket GDBPacketIO::read_packet() {
  const auto raw_packet = read_raw_packet();

  if (raw_packet.empty())
    throw std::runtime_error("Empty packet!");

  return parse_raw_packet(raw_packet);
}

void GDBPacketIO::write_packet(const GDBResponsePacket& packet) {
  const auto raw_packet = packet.to_string();
  write_raw_packet(raw_packet);
}

GDBPacketIO::RawGDBPacket GDBPacketIO::read_raw_packet() {
  char buffer[PACKET_BUFFER_MAX_SIZE];
  char *buffer_ptr = buffer;
  size_t remaining_space = sizeof(buffer);

  while (_raw_packets.empty()) {
    const auto bytes_read = read(_remote_fd, buffer_ptr, remaining_space);

    if (bytes_read == 0)
      throw std::runtime_error("Remote closed!");
    if (bytes_read < 0)
      throw std::runtime_error("Failed to read from remote FD!");

    remaining_space -= bytes_read;
    if (remaining_space == 0)
      throw std::runtime_error("Packet too long!");

    _buffer.reserve(_buffer.size() + bytes_read);
    for (auto i = 0; i < bytes_read; ++i) {
      _buffer.push_back(*buffer_ptr++);
    }
    buffer_ptr += bytes_read;

    static constexpr char PACKET_BEGIN = '$';
    static constexpr char CHECKSUM_START = '#';

    auto start = std::find(_buffer.begin(), _buffer.end(), PACKET_BEGIN);
    while (start != _buffer.end()) {
      const auto csum_start = std::find(_buffer.begin(), _buffer.end(), CHECKSUM_START);

      const auto end = csum_start + 3;
      if (end > _buffer.end())
        throw std::runtime_error("Malformed packet: missing checksum!");

      std::string contents(start+1, csum_start);
      std::string checksum_str(csum_start+1, end);
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

      start = std::find(start+1, _buffer.end(), PACKET_BEGIN);
    }

    // Remove read data from the temp buffer
    // If a packet is half-arrived, preserve its data for later
    if (start != _buffer.end())
      _buffer = Buffer(start, _buffer.end());
    else
      _buffer.clear();
  }

  const auto packet = _raw_packets.front();
  _raw_packets.pop();

  std::cout << "RECV: " << packet << std::endl;

  return packet;
}

void GDBPacketIO::write_raw_packet(const RawGDBPacket& raw_packet) {
  const uint8_t checksum = std::accumulate(raw_packet.begin(), raw_packet.end(), (uint8_t)0);

  std::stringstream ss;
  ss << "$" << raw_packet << "#";
  ss << std::hex << std::setfill('0');
  ss << std::setw(2) << (uint32_t)checksum;
  const auto ss_str = ss.str();

  std::cout << "SEND: " << ss_str << std::endl;

  std::vector<char> data(ss_str.begin(), ss_str.end());
  data.push_back('\0');

  auto remaining = data.size();
  auto data_ptr = &data[0];
  while (remaining) {
    // TODO: if == 0 then remote has closed, do something
    auto bytes_written = write(_remote_fd, data_ptr, remaining);

    if (bytes_written < 0)
      throw std::runtime_error("Failed to write to remote FD!");

    data_ptr += bytes_written;
    remaining -= bytes_written;
  }
}

GDBRequestPacket GDBPacketIO::parse_raw_packet(const RawGDBPacket &raw_packet)
{
  switch (raw_packet[0]) {
    case 'q':
      if (raw_packet == "qfThreadInfo") {
        return pkt::QueryThreadInfoRequest(raw_packet);
      }
      break;
    case '?':
      return pkt::StopReasonRequest(raw_packet);
    case 'H':
      return pkt::SetThreadRequest(raw_packet);
    case 'G':
      return pkt::GeneralRegisterWriteRequest(raw_packet);
    case 'g':
      return pkt::GeneralRegisterReadRequest(raw_packet);
    case 'M':
      return pkt::MemoryWriteRequest(raw_packet);
    case 'm':
      return pkt::MemoryReadRequest(raw_packet);
    case 'c':
      return pkt::ContinueRequest(raw_packet);
    case 'C':
      return pkt::ContinueSignalRequest(raw_packet);
    case 's':
      return pkt::StepRequest(raw_packet);
    case 'S':
      return pkt::StepSignalRequest(raw_packet);
    case 'z':
      return pkt::BreakpointInsertRequest(raw_packet);
    case 'Z':
      return pkt::BreakpointRemoveRequest(raw_packet);
    case 'R':
      return pkt::RestartRequest(raw_packet);
    case 'D':
      return pkt::DetachRequest(raw_packet);
  }

  throw UnknownPacketTypeException(raw_packet);
}
