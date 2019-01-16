//
// Copyright (C) 2018-2019 NCC Group
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#include <iostream>

#include <GDBServer/GDBPacketQueue.hpp>
#include <Util/pop_ret.hpp>

#define CHECKSUM_LENGTH 2

using xd::gdb::GDBPacket;
using xd::gdb::GDBPacketQueue;

void GDBPacketQueue::append(const std::vector<char> &data) {
  _buffer.insert(_buffer.end(), data.begin(), data.end());

  /*
   * For some ungodly reason, GDB sends interrupt requests as a raw 0x03 byte,
   * not encapsulated in a packet. As such, we have to check the intermediate
   * space between packets for 0x03s and interpret them as interrupts.
   */
  const auto find_checking_interrupts = [this](auto it, auto end, char target) {
    while (it != end && *it != target)
      if (*it++ == '\x03') {
        _packets.emplace(GDBPacket{"\x03", 0x03});
      }
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
    throw NoPacketException();

  return util::pop_ret(_packets);
}
