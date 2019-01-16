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

#ifndef XENDBG_XENEXCEPTION_HPP
#define XENDBG_XENEXCEPTION_HPP

#include <stdexcept>
#include <string>

namespace xd::xen {

  class XenException : public std::runtime_error {
  public:
    explicit XenException(const std::string& what)
        : std::runtime_error(what.c_str()), _err(0) {};

    explicit XenException(const char* what)
        : std::runtime_error(what), _err(0) {};

    explicit XenException(const std::string& what, int err)
        : std::runtime_error(what.c_str()), _err(err) {};

    explicit XenException(const char* what, int err)
        : std::runtime_error(what), _err(err) {};

    int get_err() const { return _err; };

  private:
    int _err;
  };

}

#endif //XENDBG_XENEXCEPTION_HPP
