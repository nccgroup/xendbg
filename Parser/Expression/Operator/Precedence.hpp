//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_PRECEDENCE_HPP
#define XENDBG_PRECEDENCE_HPP

#include <variant>

#include "BinaryOperator.hpp"
#include "UnaryOperator.hpp"

namespace xd::parser::expr::op {
  using Precedence = int;

  template <typename T>
  struct _precedence_impl {};

  template <> struct _precedence_impl<Equals>       { static const Precedence p = 1; };
  template <> struct _precedence_impl<Negate>       { static const Precedence p = 10; };
  template <> struct _precedence_impl<Dereference>  { static const Precedence p = 10; };
  template <> struct _precedence_impl<Add>          { static const Precedence p = 20; };
  template <> struct _precedence_impl<Subtract>     { static const Precedence p = 20; };
  template <> struct _precedence_impl<Multiply>     { static const Precedence p = 30; };
  template <> struct _precedence_impl<Divide>       { static const Precedence p = 30; };

  template <typename T>
  Precedence precedence_of() {
    return _precedence_impl<T>::p;
  }

  template <typename... Operators_t>
  Precedence precedence_of(std::variant<Operators_t...> op) {
    return std::visit([](auto&& op) {
      using Operator_t = std::decay_t<decltype(op)>;
      return precedence_of<Operator_t>();
    }, op);
  }
}

#endif //XENDBG_PRECEDENCE_HPP
