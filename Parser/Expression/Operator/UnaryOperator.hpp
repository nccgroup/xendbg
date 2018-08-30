//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_UNARYOPERATOR_HPP
#define XENDBG_UNARYOPERATOR_HPP

#include <variant>

#include "Operator.hpp"

namespace xd::parser::expr::op {

  namespace {
    using UnOp = Operator<Arity::Unary>;
  }

  struct Dereference : public UnOp {};
  struct Negate : public UnOp {};

  using UnaryOperator = std::variant<Dereference, Negate>;

}

#endif //XENDBG_UNARYOPERATOR_HPP
