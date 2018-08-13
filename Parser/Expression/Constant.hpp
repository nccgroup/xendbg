//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_EXPRESSION_CONSTANT_HPP
#define XENDBG_EXPRESSION_CONSTANT_HPP

#include "Expression.hpp"

namespace xd::parser::expr {

  class Constant : public Expression {
  public:
    explicit Constant(Expression::Value v)
        : _value(v) {};

    Expression::Value value() const { return _value; };

  private:
    Expression::Value _value;
  };

}

#endif //XENDBG_CONSTANT_HPP
