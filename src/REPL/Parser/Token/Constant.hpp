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

#ifndef XENDBG_TOKEN_CONSTANT_HPP
#define XENDBG_TOKEN_CONSTANT_HPP

#include <iostream>
#include <optional>
#include <regex>
#include <string>
#include <utility>

#include "TokenMatchResult.hpp"

namespace xd::parser::token {

  class Constant {
  public:
    using Value = uint64_t;

  public:
    explicit Constant(Value value)
        : _value(value) {}

    Value value() const { return _value; };

  private:
    Value _value;

  public:
    static TokenMatchResult<Constant> match(std::string::const_iterator begin, std::string::const_iterator end) {
      if (begin == end || *begin == '-' || *begin == '+')
        return std::make_pair(std::nullopt, begin);

      // stoi doesn't handle the 0b prefix, so we have to do this manually
      size_t base = 10;

      if ((end-begin) > 1 && *begin == '0') {
        const char base_ch = *(begin+1);
        switch (base_ch) {
          case 'b':
            base = 2;
            break;
          case 'x':
            base = 16;
            break;
          default:
            break;
        }
      }

      // Skip base the 0x/0b if found
      const size_t skip = (base != 10 ? 2 : 0);

      try {
        size_t pos;
        const auto s = std::string(begin + skip, end);
        const auto value = std::stoul(s, &pos, base);
        const auto new_begin = begin + skip + pos;

        return std::make_pair(Constant(value), new_begin);
      } catch (const std::invalid_argument &e) {
        return std::make_pair(std::nullopt, begin);
      }
    }
  };
}

#endif //XENDBG_CONSTANT_HPP
