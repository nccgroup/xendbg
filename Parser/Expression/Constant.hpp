//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_EXPRESSION_CONSTANT_HPP
#define XENDBG_EXPRESSION_CONSTANT_HPP

#include <cstddef>

#include "Expression.hpp"

namespace xd::parser::expr {

  class Constant : public Expression {
  public:
    using Value = uint64_t ;

    explicit Constant(Value v)
        : _value(v) {};

    Value value() const { return _value; };

    void evaluate(ExpressionEvaluator& evaluator) const override {
      evaluator.evaluate(*this);
    };

  private:
    Value _value;
  };

}

#endif //XENDBG_CONSTANT_HPP
