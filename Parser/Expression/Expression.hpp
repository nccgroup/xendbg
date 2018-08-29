//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_EXPRESSION_HPP
#define XENDBG_EXPRESSION_HPP

#include <memory>

#include "ExpressionEvaluator.hpp"

namespace xd::parser::expr {

  class Expression;
  using ExpressionPtr = std::shared_ptr<Expression>;

  class Expression {
  public:
    virtual void evaluate(ExpressionEvaluator& evaluator) const = 0;
  };

}

#endif //XENDBG_EXPRESSION_HPP
