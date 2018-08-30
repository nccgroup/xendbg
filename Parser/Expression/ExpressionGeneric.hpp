//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_EXPRESSION_GENERIC_HPP
#define XENDBG_EXPRESSION_GENERIC_HPP

#include <memory>
#include <variant>

#include "Operator/BinaryOperator.hpp"
#include "Operator/UnaryOperator.hpp"

namespace xd::parser::expr {

  template <typename T>
  struct Unit {
    T value;
  };

  template <typename... Units_t>
  class BinaryExpressionGeneric;

  template <typename... Units_t>
  class UnaryExpressionGeneric;

  template <typename... Units_t>
  struct ExpressionGeneric {
  private:
    using UnaryExpression = UnaryExpressionGeneric<Units_t...>;
    using BinaryExpression = BinaryExpressionGeneric<Units_t...>;

  public:
    using UnaryExpressionPtr = std::unique_ptr<UnaryExpression>;
    using BinaryExpressionPtr = std::unique_ptr<BinaryExpression>;

    template <typename T>
    static ExpressionGeneric<Units_t...> make(T value) {
      return ExpressionGeneric<Units_t...>{value};
    }

    static ExpressionGeneric<Units_t...> make(
        op::UnaryOperator op, const ExpressionGeneric<Units_t...> &x)
    {
      return ExpressionGeneric<Units_t...>{std::make_shared<UnaryExpression>(op, x)};
    }

    static ExpressionGeneric<Units_t...> make(
        op::BinaryOperator op, const ExpressionGeneric<Units_t...> &x, const ExpressionGeneric<Units_t...> &y)
    {
      return ExpressionGeneric<Units_t...>{std::make_shared<BinaryExpression>(op, x, y)};
    }

    enum class Arity {
      Binary,
      Unary,
      Nullary
    };

    Arity arity() const {
      if (std::holds_alternative<BinaryExpressionPtr>(value))
        return Arity::Binary;
      else if (std::holds_alternative<BinaryExpressionPtr>(value))
        return Arity::Unary;
      else
        return Arity::Nullary;
    };

    std::variant<Units_t..., UnaryExpressionPtr, BinaryExpressionPtr> value;
  };

  template <typename... Units_t>
  struct UnaryExpressionGeneric {
  private:
    using Expression = ExpressionGeneric<Units_t...>;

  public:
    UnaryExpressionGeneric(op::UnaryOperator op, Expression x)
      : op(op), x(x) {};

    op::UnaryOperator op;
    Expression x;
  };

  template <typename... Units_t>
  struct BinaryExpressionGeneric {
  private:
    using Expression = ExpressionGeneric<Units_t...>;

  public:
    BinaryExpressionGeneric(op::BinaryOperator op, Expression x)
        : op(op), x(x), y(y) {};

    op::BinaryOperator op;
    Expression x, y;
  };

}

#endif //XENDBG_EXPRESSION_GENERIC_HPP
