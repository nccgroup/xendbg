//
// Created by Spencer Michaels on 9/20/18.
//

#include "GDBPacketQueue.hpp"
#include "../Util/pop_ret.hpp"

#define CHECKSUM_LENGTH 2

using xd::gdbsrv::GDBPacketQueue;

void GDBPacketQueue::enqueue(std::vector<char> data) {
  _buffer.insert(_buffer.end(), data.begin(), data.end());

  auto end = _buffer.begin();
  while (end != _buffer.end()) {
    auto packet_start = std::find(end, _buffer.end(), '$');
    auto chksum_start = std::find(packet_start, _buffer.end(), '#');

    if (packet_start == _buffer.end() ||
        chksum_start == _buffer.end() ||
        _buffer.end() - chksum_start < (CHECKSUM_LENGTH + 2))
      break;

    end = chksum_start + CHECKSUM_LENGTH + 1;
    _packets.emplace(GDBPacket{
      std::string(packet_start, checksum_start),
      std::stoul(std::string(checksum_start, end), 0, 16)
    })
    _packets.push(std::string(packet_start, end));
  }

  end = std::find(end, _buffer.end(), '$');
  _buffer.erase(_buffer.begin(), end);
}

std::optional<GDBPacket> GDBPacketQueue::dequeue() {
  if (_packets.empty())
    return std::nullopt;

  return util::pop_ret(_packets);
}
