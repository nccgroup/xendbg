//
// Created by Spencer Michaels on 8/29/18.
//

#ifndef XENDBG_EXPRESSIONEVALUATOR_HPP
#define XENDBG_EXPRESSIONEVALUATOR_HPP

namespace xd {

  class BinaryExpression;
  class Constant;
  class Label;
  class UnaryExpression;
  class Variable;

  class ExpressionEvaluator {
  public:
    virtual void evaluate(const BinaryExpression& ex) = 0;
    virtual void evaluate(const Constant& ex) = 0;
    virtual void evaluate(const Label& ex) = 0;
    virtual void evaluate(const UnaryExpression& ex) = 0;
    virtual void evaluate(const Variable& ex) = 0;
  };

}

#endif //XENDBG_EXPRESSIONEVALUATOR_HPP
