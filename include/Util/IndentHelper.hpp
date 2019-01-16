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

#ifndef XENDBG_INDENT_HELPER_HPP
#define XENDBG_INDENT_HELPER_HPP

#include <cstddef>
#include <ostream>
#include <iostream>

namespace xd::util {

  class IndentHelper {
    public:
      IndentHelper(size_t indent_size = 2, bool use_tabs = false)
        : _indent_size(indent_size), _indent_level(0), _use_tabs(use_tabs) {};

      void indent(size_t i = 1) { _indent_level += i; };
      void unindent(size_t i = 1) { _indent_level -= i; };

      std::string make_indent() const {
        const char c = _use_tabs ? '\t' : ' ';
        if (_indent_level == 0)
          return "";
        return std::string(_indent_level * _indent_size, c);
      };

    private:
      size_t _indent_size, _indent_level;
      bool _use_tabs;
  };

}

std::ostream &operator<<(std::ostream &out, const xd::util::IndentHelper &indent);

#endif //XENDBG_INDENT_HELPER_HPP
