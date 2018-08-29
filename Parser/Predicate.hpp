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

namespace xd::parser::op {
  class Sentinel;
}

namespace xd::parser::pred {

  template<typename Token_t>
  bool is_sentinel(Token_t token) {
    return std::holds_alternative<op::Sentinel>(token);
  }

  template <typename Token_t>
  bool is_constant(Token_t token) {
    return std::holds_alternative<token::Constant>(token);
  }

  template <typename Token_t>
  bool is_label(Token_t token) {
    return std::holds_alternative<token::Label>(token);
  }

  template <typename Token_t>
  bool is_symbol(Token_t token) {
    return std::holds_alternative<token::Symbol>(token);
  }

  template <typename Token_t>
  bool is_symbol_of_type(Token_t token, const token::Symbol::Type& sym) {
    return std::holds_alternative<token::Symbol>(token) && std::get<token::Symbol>(token).type() == sym;
  }

  template <typename Token_t>
  bool is_variable(Token_t token) {
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
