//
// Created by Spencer Michaels on 8/11/18.
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
          return std::make_pair(std::optional<Symbol>(), begin);
      }

      return std::make_pair(Symbol(type), begin + 1);
    }
  };;

}

#endif //XENDBG_SYMBOL_HPP
