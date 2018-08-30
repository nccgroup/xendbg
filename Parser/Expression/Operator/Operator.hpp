//
// Created by Spencer Michaels on 8/30/18.
//

#ifndef XENDBG_OPERATOR_HPP
#define XENDBG_OPERATOR_HPP

namespace xd::parser::expr::op {

  enum class Arity {
    Binary,
    Unary,
    Nullary
  };

  template <Arity Arity_value>
  struct Operator {
    static const Arity arity = Arity_value;
  };

}

#endif //XENDBG_OPERATOR_HPP
