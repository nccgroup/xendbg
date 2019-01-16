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

#ifndef XENDBG_GDBPACKET_HPP
#define XENDBG_GDBPACKET_HPP

#include <cstddef>
#include <string>

namespace xd::gdb {

  class GDBPacket {
  public:
    explicit GDBPacket(std::string contents);
    GDBPacket(std::string contents, uint8_t checksum);

    const std::string &get_contents() const { return _contents; };
    const uint8_t &get_checksum() const { return _checksum; };

    std::string to_string() const;

    bool is_checksum_valid() const;
    bool starts_with(const std::string &s) const;

  private:
    std::string _contents;
    uint8_t _checksum;

    uint8_t calculate_checksum() const;
  };

}

#endif //XENDBG_GDBPACKET_HPP
