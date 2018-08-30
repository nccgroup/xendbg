//
// Created by Spencer Michaels on 8/30/18.
//

#ifndef XENDBG_EXPRESSION_HPP
#define XENDBG_EXPRESSION_HPP

#include <string>

#include "ExpressionGeneric.hpp"

namespace xd::parser::expr {

  using Constant = Unit<uint64_t>;
  using Label = Unit<std::string>;
  using Variable = Unit<std::string>;

  using Expression = ExpressionGeneric<Constant, Label, Variable>;

}

#endif //XENDBG_EXPRESSION_HPP
