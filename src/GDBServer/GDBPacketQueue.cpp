//
// Created by Spencer Michaels on 9/20/18.
//

#include <iostream>

#include "GDBPacketQueue.hpp"
#include "../Util/pop_ret.hpp"

#define CHECKSUM_LENGTH 2

using xd::gdbsrv::GDBPacket;
using xd::gdbsrv::GDBPacketQueue;

void GDBPacketQueue::append(const std::vector<char> &data) {
  _buffer.insert(_buffer.end(), data.begin(), data.end());

  /*
   * For some ungodly reason, GDB sends interrupt requests as a raw 0x03 byte,
   * not encapsulated in a packet. As such, we have to check the intermediate
   * space between packets for 0x03s and interpret them as interrupts.
   */
  const auto find_checking_interrupts = [this](auto it, auto end, char target) {
    while (it != end && *it != target)
      if (*it++ == '\x03')
        _packets.emplace(GDBPacket{"\x03", 0x03});
    return it;
  };

  auto end = _buffer.begin();
  while (end != _buffer.end()) {
    auto packet_start = find_checking_interrupts(end, _buffer.end(), '$');
    auto checksum_start = std::find(packet_start, _buffer.end(), '#');

    if (packet_start == _buffer.end() ||
        checksum_start == _buffer.end() ||
        _buffer.end() - checksum_start < (CHECKSUM_LENGTH + 1))
      break;

    end = checksum_start + CHECKSUM_LENGTH + 1;
    _packets.emplace(GDBPacket{
      std::string(packet_start+1, checksum_start),
      static_cast<uint8_t>(std::stoul(std::string(checksum_start+1, end), 0, 16))
    });
  }

  end = find_checking_interrupts(end, _buffer.end(), '$');
  _buffer.erase(_buffer.begin(), end);
}

GDBPacket GDBPacketQueue::pop() {
  if (_packets.empty())
    throw std::runtime_error("No packets!");

  return util::pop_ret(_packets);
}
