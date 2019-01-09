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
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_TOKEN_PREDICATE_HPP
#define XENDBG_TOKEN_PREDICATE_HPP

#include <variant>

#include "Token/Constant.hpp"
#include "Token/Label.hpp"
#include "Token/Symbol.hpp"
#include "Token/Variable.hpp"

namespace xd::parser::expr::op {
  class Sentinel;
}

namespace xd::parser::pred {

  template<typename Token_t>
  bool is_sentinel(const Token_t& token) {
    return std::holds_alternative<expr::op::Sentinel>(token);
  }

  template <typename Token_t>
  bool is_constant(const Token_t& token) {
    return std::holds_alternative<token::Constant>(token);
  }

  template <typename Token_t>
  bool is_label(const Token_t& token) {
    return std::holds_alternative<token::Label>(token);
  }

  template <typename Token_t>
  bool is_symbol(const Token_t& token) {
    return std::holds_alternative<token::Symbol>(token);
  }

  template <typename Token_t>
  bool is_symbol_of_type(const Token_t& token, const token::Symbol::Type& sym) {
    return std::holds_alternative<token::Symbol>(token) && std::get<token::Symbol>(token).type() == sym;
  }

  template <typename Token_t>
  bool is_variable(const Token_t& token) {
    return std::holds_alternative<token::Variable>(token);
  }

  template <typename Token_t>
  bool is_binary_operator_symbol(const Token_t& token) {
    return is_symbol_of_type(token, token::Symbol::Type::Plus) ||
           is_symbol_of_type(token, token::Symbol::Type::Minus) ||
           is_symbol_of_type(token, token::Symbol::Type::Star) ||
           is_symbol_of_type(token, token::Symbol::Type::Slash) ||
           is_symbol_of_type(token, token::Symbol::Type::Equals);
  };

  template <typename Token_t>
  bool is_unary_operator_symbol(const Token_t& token) {
    return is_symbol_of_type(token, token::Symbol::Type::Minus) ||
           is_symbol_of_type(token, token::Symbol::Type::Star);
  };

}

#endif //XENDBG_PREDICATE_HPP
