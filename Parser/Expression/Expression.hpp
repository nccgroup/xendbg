//
// Created by Spencer Michaels on 8/30/18.
//

#ifndef XENDBG_EXPRESSION_HPP
#define XENDBG_EXPRESSION_HPP

#include <string>

#include "ExpressionGeneric.hpp"

namespace xd::parser::expr {

  struct Constant : public Unit<uint64_t> {};
  struct Label : public Unit<std::string> {};
  struct Variable : public Unit<std::string> {};

  using Expression = ExpressionGeneric<Constant, Label, Variable>;

}

#endif //XENDBG_EXPRESSION_HPP
