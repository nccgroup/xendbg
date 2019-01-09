//
// Copyright (C) 2018-2019 Spencer Michaels
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

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
  public:
    using UnaryExpression = UnaryExpressionGeneric<Units_t...>;
    using BinaryExpression = BinaryExpressionGeneric<Units_t...>;
    using UnaryExpressionPtr = std::unique_ptr<UnaryExpression>;
    using BinaryExpressionPtr = std::unique_ptr<BinaryExpression>;

    template <typename T>
    ExpressionGeneric(T v) : _value(v) {}

    ExpressionGeneric(op::UnaryOperator op, ExpressionGeneric x)
      : _value(std::make_unique<UnaryExpression>(op, std::move(x))) {};

    ExpressionGeneric(op::BinaryOperator op, ExpressionGeneric x, ExpressionGeneric y)
      : _value(std::make_unique<BinaryExpression>(op, std::move(x), std::move(y))) {};

    template <typename T>
    bool is_of_type() const {
      return std::holds_alternative<T>(_value);
    }
    bool is_unex() const {
      return is_of_type<UnaryExpressionPtr>();
    }
    bool is_binex() const {
      return is_of_type<BinaryExpressionPtr>();
    }

    template <typename T>
    const T& as() const {
      return std::get<T>(_value);
    }
    const UnaryExpression& as_unex() const {
      return *std::get<UnaryExpressionPtr>(_value);
    }
    const BinaryExpression& as_binex() const {
      return *std::get<BinaryExpressionPtr>(_value);
    }

    template <typename F>
    void visit(F f) const {
      std::visit(f, _value);
    }

    template <typename R, typename F>
    R visit(F f) const {
      return std::visit(f, _value);
    }

  private:
    std::variant<Units_t..., UnaryExpressionPtr, BinaryExpressionPtr> _value;
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
