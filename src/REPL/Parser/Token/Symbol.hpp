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

#ifndef XENDBG_TOKEN_SYMBOL_HPP
#define XENDBG_TOKEN_SYMBOL_HPP

#include <optional>
#include <regex>
#include <string>
#include <utility>

#include "TokenMatchResult.hpp"

namespace xd::parser::token {

  class Symbol {
  public:
    enum class Type {
      Plus,
      Minus,
      Star,
      Slash,
      ParenLeft,
      ParenRight,
      Equals,
    };

  public:
    explicit Symbol(Type type)
        : _type(type) {}

    Type type() const { return _type; };

  private:
    Type _type;

  public:
    static TokenMatchResult<Symbol> match(std::string::const_iterator begin, std::string::const_iterator end) {
      using Type = Symbol::Type;

      Type type;
      switch (*begin) {
        case '+':
          type = Type::Plus;
          break;
        case '-':
          type = Type::Minus;
          break;
        case '*':
          type = Type::Star;
          break;
        case '/':
          type = Type::Slash;
          break;
        case '(':
          type = Type::ParenLeft;
          break;
        case ')':
          type = Type::ParenRight;
          break;
        case '=':
          type = Type::Equals;
          break;
        default:
          return std::make_pair(std::nullopt, begin);
      }

      return std::make_pair(Symbol(type), begin + 1);
    }
  };;

}

#endif //XENDBG_SYMBOL_HPP
