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

#ifndef XENDBG_GDBRESPONSEBASE_HPP
#define XENDBG_GDBRESPONSEBASE_HPP

#include <iomanip>
#include <sstream>
#include <string>

namespace xd::gdb::rsp {

  namespace {
    // Writes the bytes of a value of arbitrary size in guest order
    template <typename Value_t>
    void write_bytes(std::stringstream &ss, Value_t value) {
      auto *p = (unsigned char*)&value;
      auto *end = p + sizeof(Value_t);

      ss << std::hex << std::setfill('0');
      while (p != end)
        ss << std::setw(2) << (unsigned)(*p++);
    }

    void write_byte(std::stringstream &ss, uint8_t byte) {
      ss << std::hex << std::setfill('0');
      ss << std::setw(2) << (unsigned)byte;
    }

    std::string hexify(const std::string& s) {
      std::stringstream ss;
      ss << std::hex << std::setfill('0');
      for (const unsigned char c : s)
        ss << std::setw(2) << (unsigned)c;
      return ss.str();
    }

    template <typename Value_t>
    void add_list_entry(std::stringstream &ss, Value_t value) {
      ss << value;
      ss << ",";
    }

    template <typename Key_t, typename Value_t>
    void add_map_entry(std::stringstream &ss, Key_t key, Value_t value) {
      ss << key;
      ss << ":";
      ss << value;
      ss << ";";
    }
  }

  class GDBResponse {
  public:
    virtual ~GDBResponse() = default;
    virtual std::string to_string() const = 0;
  };

}

#endif //XENDBG_GDBRESPONSEBASE_HPP
