//
// Created by Spencer Michaels on 10/2/18.
//

#include <iomanip>
#include <numeric>
#include <sstream>

#include <GDBServer/GDBPacket.hpp>

using xd::gdb::GDBPacket;

GDBPacket::GDBPacket(std::string contents)
    : _contents(std::move(contents)), _checksum(calculate_checksum())
{
}

GDBPacket::GDBPacket(std::string contents, uint8_t checksum)
  : _contents(std::move(contents)), _checksum(checksum)
{
}

std::string GDBPacket::to_string() {
  std::stringstream ss;
  ss << "$" << _contents << "#";
  ss << std::hex << std::setfill('0') << std::setw(2);
  ss << (unsigned)_checksum;
  return ss.str();
}

bool GDBPacket::is_checksum_valid() const {
  return _checksum == calculate_checksum();
}

uint8_t GDBPacket::calculate_checksum() const {
  return std::accumulate(_contents.begin(), _contents.end(), (uint8_t)0);
}

bool starts_with(const std::string &s) {
  // TODO
}
