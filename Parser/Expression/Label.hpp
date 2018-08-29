//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_EXPRESSION_LABEL_HPP
#define XENDBG_EXPRESSION_LABEL_HPP

#include <string>

#include "Expression.hpp"

namespace xd::parser::expr {

  class Label : public Expression {
  public:
    explicit Label(std::string n)
        : _name(std::move(n)) {};

    const std::string& name() const { return _name; };

    void evaluate(ExpressionEvaluator& evaluator) const override {
      evaluator.evaluate(*this);
    };

  private:
    std::string _name;
  };

}

#endif //XENDBG_EXPRESSION_LABEL_HPP
