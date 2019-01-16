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

#ifndef XENDBG_PRECEDENCE_HPP
#define XENDBG_PRECEDENCE_HPP

#include <variant>

#include "BinaryOperator.hpp"
#include "UnaryOperator.hpp"

namespace xd::parser::expr::op {
  using Precedence = int;

  template <typename T>
  struct _precedence{};

  template <> struct _precedence<Equals>      { static const Precedence p = 1; };
  template <> struct _precedence<Negate>      { static const Precedence p = 10; };
  template <> struct _precedence<Add>         { static const Precedence p = 20; };
  template <> struct _precedence<Subtract>    { static const Precedence p = 20; };
  template <> struct _precedence<Multiply>    { static const Precedence p = 30; };
  template <> struct _precedence<Divide>      { static const Precedence p = 30; };
  template <> struct _precedence<Dereference> { static const Precedence p = 50; };

  template <typename T>
  Precedence precedence_of(const T&) {
    return _precedence<T>::p;
  }

  template <typename... Operators_t>
  Precedence precedence_of(const std::variant<Operators_t...>& op) {
    return std::visit([](auto&& op) {
      return precedence_of(op);
    }, op);
  }
}

#endif //XENDBG_PRECEDENCE_HPP
