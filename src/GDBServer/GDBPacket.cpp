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

std::string GDBPacket::to_string() const {
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

bool GDBPacket::starts_with(const std::string &s) const {
  return s.size() <= _contents.size() &&
    std::equal(s.begin(), s.end(), _contents.begin(), _contents.begin() + s.size());
}
