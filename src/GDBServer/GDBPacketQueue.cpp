//
// Created by Spencer Michaels on 9/20/18.
//

#include "GDBPacketQueue.hpp"
#include "../Util/pop_ret.hpp"

using xd::gdbsrv::GDBPacketQueue;

void GDBPacketQueue::enqueue(std::vector<char> data) {
  _buffer.insert(_buffer.end(), data.begin(), data.end());

  auto start = _buffer.begin();
  while (start != _buffer.end()) {
    auto packet_start = std::find(start, _buffer.end(), '$');
    auto chksum_start = std::find(packet_start, _buffer.end(), '#');

    if (packet_start == _buffer.end() ||
        chksum_start == _buffer.end() ||
        _buffer.end() - chksum_start < 4)
      break;

    _packets.push(std::string(packet_start, chksum_start+4));
    start = chksum_start + 4;
  }

  start = std::find(start, _buffer.end(), '$');
  _buffer.erase(_buffer.begin(), start);
}

std::optional<std::string> GDBPacketQueue::dequeue() {
  if (_packets.empty())
    return std::nullopt;

  return util::pop_ret(_packets);
}
