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

#ifndef XENDBG_GDBSTEPCONTINUEREQUEST_HPP
#define XENDBG_GDBSTEPCONTINUEREQUEST_HPP

#include "GDBRequestBase.hpp"

#define DECLARE_SIGNAL_REQUESTS(name1, ch1, name2, ch2) \
  DECLARE_SIMPLE_REQUEST(name1, ch1); \
  class name2 : public GDBRequestBase { \
  public: \
    explicit name2(const std::string &data) \
      : GDBRequestBase(data, ch2), _signal(0) \
    { \
      _signal = read_byte(); \
      expect_end(); \
    }; \
    uint8_t get_signal() { return _signal; }; \
  private: \
    uint8_t _signal; \
  }

namespace xd::gdb::req {

  DECLARE_SIGNAL_REQUESTS(ContinueRequest, 'c', ContinueSignalRequest, 'C');
  DECLARE_SIGNAL_REQUESTS(StepRequest, 's', StepSignalRequest, 'S');

}

#endif //XENDBG_GDBSTEPCONTINUEREQUEST_HPP
