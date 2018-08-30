//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_UNARYOPERATOR_HPP
#define XENDBG_UNARYOPERATOR_HPP

#include <variant>

namespace xd::parser::expr::op {

  struct UnaryOperatorBase {};

  struct Dereference : public UnaryOperatorBase {};
  struct Negate : public UnaryOperatorBase {};

  using UnaryOperator = std::variant<Dereference, Negate>;

}

#endif //XENDBG_UNARYOPERATOR_HPP
