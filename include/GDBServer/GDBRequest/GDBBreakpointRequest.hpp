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

#ifndef XENDBG_GDBBREAKPOINTREQUEST_HPP
#define XENDBG_GDBBREAKPOINTREQUEST_HPP

#include "GDBRequestBase.hpp"

#define DECLARE_BREAKPOINT_REQUEST(name, ch) \
  class name : public GDBRequestBase { \
  public: \
    explicit name(const std::string &data) \
      : GDBRequestBase(data, ch) \
    { \
      _type = read_hex_number<uint8_t>(); \
      expect_char(','); \
      _address = read_hex_number<uint64_t>(); \
      expect_char(','); \
      _kind = read_hex_number<uint8_t>(); \
      expect_end(); \
    }; \
    uint64_t get_address() const { return _address; }; \
    uint8_t get_type() const { return _type; }; \
    uint8_t get_kind() const { return _kind; }; \
  private: \
    uint64_t _address; \
    uint8_t _type, _kind; \
  }

namespace xd::gdb::req {

  DECLARE_BREAKPOINT_REQUEST(BreakpointInsertRequest, 'Z');
  DECLARE_BREAKPOINT_REQUEST(BreakpointRemoveRequest, 'z');

}

#endif //XENDBG_GDBBREAKPOINTREQUEST_HPP
