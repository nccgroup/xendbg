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
  struct BinaryExpressionGeneric;

  template <typename... Units_t>
  struct UnaryExpressionGeneric;

  template <typename... Units_t>
  struct ExpressionGeneric {
  private:
    using UnaryExpression = UnaryExpressionGeneric<Units_t...>;
    using BinaryExpression = BinaryExpressionGeneric<Units_t...>;

  public:
    using UnaryExpressionPtr = std::unique_ptr<UnaryExpression>;
    using BinaryExpressionPtr = std::unique_ptr<BinaryExpression>;

    template <typename T>
    ExpressionGeneric(T v) : value(v) {}

    ExpressionGeneric(op::UnaryOperator op, ExpressionGeneric x)
      : value(std::make_unique<UnaryExpression>(op, std::move(x))) {};

    ExpressionGeneric(op::BinaryOperator op, ExpressionGeneric x, ExpressionGeneric y)
      : value(std::make_unique<BinaryExpression>(op, std::move(x), std::move(y))) {};

    std::variant<Units_t..., UnaryExpressionPtr, BinaryExpressionPtr> value;
  };

  template <typename... Units_t>
  struct UnaryExpressionGeneric {
  private:
    using Expression = ExpressionGeneric<Units_t...>;

  public:
    UnaryExpressionGeneric(op::UnaryOperator op, Expression x)
      : op(op), x(std::move(x)) {};

    op::UnaryOperator op;
    Expression x;
  };

  template <typename... Units_t>
  struct BinaryExpressionGeneric {
  private:
    using Expression = ExpressionGeneric<Units_t...>;

  public:
    BinaryExpressionGeneric(op::BinaryOperator op, Expression x, Expression y)
        : op(op), x(std::move(x)), y(std::move(y)) {};

    op::BinaryOperator op;
    Expression x, y;
  };

}

#endif //XENDBG_EXPRESSION_GENERIC_HPP
