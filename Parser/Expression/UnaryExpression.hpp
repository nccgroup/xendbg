//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_UNARYEXPRESSION_HPP
#define XENDBG_UNARYEXPRESSION_HPP

#include "Expression.hpp"
#include "../Operator/UnaryOperator.hpp"

namespace xd::parser::expr {

  class UnaryExpression : public Expression {
  public:
    explicit UnaryExpression(op::UnaryOperator op, ExpressionPtr x)
        : _op(op), _x(std::move(x)) {};

    ExpressionPtr x() const { return _x; }
    op::UnaryOperator op() const { return _op; }

    void evaluate(ExpressionEvaluator& evaluator) const override {
      evaluator(*this);
    };

  private:
    op::UnaryOperator _op;
    ExpressionPtr _x;
  };

}

#endif //XENDBG_UNARYEXPRESSION_HPP
