//
// Created by Spencer Michaels on 8/29/18.
//

#ifndef XENDBG_EXPRESSIONEVALUATOR_HPP
#define XENDBG_EXPRESSIONEVALUATOR_HPP

namespace xd::parser::expr {

  class BinaryExpression;
  class Constant;
  class Label;
  class UnaryExpression;
  class Variable;

  class ExpressionEvaluator {
  public:
    virtual void operator()(const BinaryExpression& ex) = 0;
    virtual void operator()(const Constant& ex) = 0;
    virtual void operator()(const Label& ex) = 0;
    virtual void operator()(const UnaryExpression& ex) = 0;
    virtual void operator()(const Variable& ex) = 0;
  };

}

#endif //XENDBG_EXPRESSIONEVALUATOR_HPP
