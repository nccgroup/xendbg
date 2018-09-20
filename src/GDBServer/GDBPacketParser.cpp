#include <iostream>
#include <numeric>
#include <sstream>
#include <string>

#include <unistd.h>

#include "GDBPacketParser.hpp"
#include "GDBRequestPacket.hpp"
#include "../Util/pop_ret.hpp"
#include "../Util/string.hpp"

GDBPacketParser::RawGDBPacket GDBPacketParser::read_raw_packet() {
  char buffer[PACKET_BUFFER_MAX_SIZE];
  char *buffer_ptr = buffer;
  size_t remaining_space = sizeof(buffer);

  while (_raw_packets.empty()) {
    const auto bytes_read = recv(_remote_fd, buffer_ptr, remaining_space, 0);

    if (bytes_read == 0)
      throw std::runtime_error("Remote closed!");
    if (bytes_read < 0)
      throw std::runtime_error("Failed to read from remote FD!");

    remaining_space -= bytes_read;
    if (remaining_space == 0)
      throw std::runtime_error("Packet too long!");

    // TODO: Is there a more efficient way to do this?
    _buffer.reserve(_buffer.size() + bytes_read);
    //std::cout << "BUF:  ";
    for (auto i = 0; i < bytes_read; ++i) {
      //std::cout << *buffer_ptr;
      _buffer.push_back(*buffer_ptr++);
    }
    //std::cout << std::endl;

    static constexpr char PACKET_BEGIN = '$';
    static constexpr char CHECKSUM_START = '#';

    auto start = std::find(_buffer.begin(), _buffer.end(), PACKET_BEGIN);
    auto csum_start = std::find(_buffer.begin(), _buffer.end(), CHECKSUM_START);
    while (start != _buffer.end() && csum_start != _buffer.end()) {
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
        if (_ack_enabled) {
          send(_remote_fd, "+", 1, 0);
        }
        _raw_packets.push(RawGDBPacket{contents});
      } else if (_ack_enabled) {
        send(_remote_fd, "-", 1, 0);
      }

      start = std::find(start+1, _buffer.end(), PACKET_BEGIN);
      csum_start = std::find(start, _buffer.end(), CHECKSUM_START);
    }

    // Remove read data from the temp buffer
    // If a packet is half-arrived, preserve its data for later
    if (start != _buffer.end())
      _buffer = Buffer(start, _buffer.end());
    else
      _buffer.clear();

    //std::cout << "REMN: " << std::string(_buffer.begin(), _buffer.end()) << std::endl;
  }

  const auto packet = _raw_packets.front();
  _raw_packets.pop();

  std::cout << "RECV: " << packet << std::endl;

  return packet;
}

GDBRequestPacket GDBPacketParser::parse_raw_packet(const RawGDBPacket &raw_packet) {
  switch (raw_packet[0]) {
    case 'q':
      if (raw_packet == "qfThreadInfo")
        return pkt::QueryThreadInfoStartRequest(raw_packet);
      else if (raw_packet == "qsThreadInfo")
        return pkt::QueryThreadInfoContinuingRequest(raw_packet);
      else if (raw_packet == "qC")
        return pkt::QueryCurrentThreadIDRequest(raw_packet);
      else if (is_prefix(std::string("qSupported"), raw_packet))        // TODO
        return pkt::QuerySupportedRequest(raw_packet);
      else if ("qHostInfo" == raw_packet)
        return pkt::QueryHostInfoRequest(raw_packet);
      else if ("qProcessInfo" == raw_packet)
        return pkt::QueryProcessInfoRequest(raw_packet);
      else if (is_prefix(std::string("qRegisterInfo"), raw_packet))     // TODO
        return pkt::QueryRegisterInfoRequest(raw_packet);
      else if (is_prefix(std::string("qMemoryRegionInfo"), raw_packet)) // TODO
        return pkt::QueryMemoryRegionInfoRequest(raw_packet);
      break;
    case 'Q':
      if (raw_packet == "QStartNoAckMode")
        return pkt::StartNoAckModeRequest(raw_packet);
      else if (raw_packet == "QThreadSuffixSupported")
        return pkt::QueryThreadSuffixSupportedRequest(raw_packet);
      else if (raw_packet == "QListThreadsInStopReply")
        return pkt::QueryListThreadsInStopReplySupportedRequest(raw_packet);
      break;
    case '?':
      return pkt::StopReasonRequest(raw_packet);
    case 'k':
      return pkt::KillRequest(raw_packet);
    case 'H':
      return pkt::SetThreadRequest(raw_packet);
    case 'p':
      return pkt::RegisterReadRequest(raw_packet);
    case 'P':
      return pkt::RegisterWriteRequest(raw_packet);
    case 'G':
      return pkt::GeneralRegistersBatchWriteRequest(raw_packet);
    case 'g':
      return pkt::GeneralRegistersBatchReadRequest(raw_packet);
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
    case 'Z':
      return pkt::BreakpointInsertRequest(raw_packet);
    case 'z':
      return pkt::BreakpointRemoveRequest(raw_packet);
    case 'R':
      return pkt::RestartRequest(raw_packet);
    case 'D':
      return pkt::DetachRequest(raw_packet);
  }

  throw UnknownPacketTypeException(raw_packet);
}
