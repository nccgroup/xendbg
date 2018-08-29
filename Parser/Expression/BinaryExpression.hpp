//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_BINARYEXPRESSION_HPP
#define XENDBG_BINARYEXPRESSION_HPP

#include "Expression.hpp"
#include "../Operator/BinaryOperator.hpp"

namespace xd::parser::expr {

  class BinaryExpression : public Expression {
  public:
    BinaryExpression(op::BinaryOperator op, ExpressionPtr x, ExpressionPtr y)
        : _op(op), _x(std::move(x)), _y(std::move(y)) {};

    op::BinaryOperator op() const { return _op; }
    ExpressionPtr x() const { return _x; }
    ExpressionPtr y() const { return _y; }

    void evaluate(ExpressionEvaluator& evaluator) const override {
      evaluator.evaluate(*this);
    };

  private:
    op::BinaryOperator _op;
    ExpressionPtr _x, _y;
  };
}

#endif //XENDBG_BINARYEXPRESSION_HPP
