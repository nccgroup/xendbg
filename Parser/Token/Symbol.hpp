//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_TOKEN_SYMBOL_HPP
#define XENDBG_TOKEN_SYMBOL_HPP

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
  };;

}

#endif //XENDBG_SYMBOL_HPP
