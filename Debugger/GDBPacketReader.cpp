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
  : _remote_fd(remote_fd), _buffer_pos(0)
{
  memset(_buffer, 0xFF, sizeof(_buffer));
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

  return parse_packet(packet.contents);
}

GDBPacketReader::RawGDBPacket GDBPacketReader::read_packet() {
  char *buffer_ptr = _buffer;
  size_t remaining_space = sizeof(_buffer);

  while (_raw_packets.empty()) {
    const size_t bytes_read = read(_remote_fd, buffer_ptr, remaining_space);
    buffer_ptr += bytes_read;
    remaining_space -= bytes_read;

    if (remaining_space == 0)
      throw std::runtime_error("Packet too long!");

    char *start = strchr(_buffer, '$');
    char *chksum = strchr(start, '#');
    char *end = strchr(chksum, '\0');
    while (start && chksum && end) {
      // Skip beyond the start-of-packet and checksum delimiters
      start++;
      chksum++;

      // NOTE: checksum is not validated here, just read
      _raw_packets.push(RawGDBPacket{
          std::string(start, end-start-2),
          (uint8_t)((chksum[0] << 4) + chksum[1])
      });

      start = strchr(end, '$');
      chksum = strchr(start, '#');
      end = strchr(chksum, '\0');
    }

    if (start) {
      // Move the remaining data to the front of the buffer.
      char tmp_buffer[sizeof(_buffer)];
      const size_t copy_size = sizeof(_buffer) - (start - _buffer);
      memcpy(tmp_buffer, start, copy_size);
      memcpy(_buffer, tmp_buffer, copy_size);
      // Ensure no spurious null bytes are present
      memset(_buffer + copy_size, 0xFF, sizeof(_buffer) - copy_size);
    }
    _buffer_pos = 0;
  }

  const auto raw_packet = _raw_packets.front();
  _raw_packets.pop();

  return raw_packet;
}

GDBPacket GDBPacketReader::parse_packet(const std::string &buffer)
{
  size_t buffer_pos = 0;

  switch (buffer_pos++) {
    // TODO
  }

  throw std::runtime_error("Unknown packet type!");
}
