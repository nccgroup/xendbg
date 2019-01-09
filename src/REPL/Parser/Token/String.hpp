//
// Copyright (C) 2018-2019 Spencer Michaels
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

//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_TOKEN_STRING_HPP
#define XENDBG_TOKEN_STRING_HPP

#include <optional>
#include <regex>
#include <string>
#include <utility>

#include "TokenMatchResult.hpp"
#include "../../../Util/string.hpp"

namespace xd::parser::token {

  class String {
  public:
    using Value = std::string;

  public:
    explicit String(Value value)
        : _value(std::move(value)) {}

    const Value& value() const { return _value; };

  private:
    Value _value;

  public:
    static TokenMatchResult<String> match(std::string::const_iterator begin, std::string::const_iterator end) {
      const auto new_end = util::string::match_optionally_quoted_string(begin, end);
      const auto value = std::string(begin, new_end);
      return std::make_pair(String(value), new_end);
    };
  };

}

#endif //XENDBG_TOKEN_STRING_HPP
