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
  struct _precedence{};

  template <> struct _precedence<Equals>      { static const Precedence p = 1; };
  template <> struct _precedence<Negate>      { static const Precedence p = 10; };
  template <> struct _precedence<Dereference> { static const Precedence p = 10; };
  template <> struct _precedence<Add>         { static const Precedence p = 20; };
  template <> struct _precedence<Subtract>    { static const Precedence p = 20; };
  template <> struct _precedence<Multiply>    { static const Precedence p = 30; };
  template <> struct _precedence<Divide>      { static const Precedence p = 30; };

  template <typename T>
  Precedence precedence_of(const T&) {
    return _precedence<T>::p;
  }

  template <typename... Operators_t>
  Precedence precedence_of(const std::variant<Operators_t...>& op) {
    return std::visit([](auto&& op) {
      return precedence_of(op);
    }, op);
  }
}

#endif //XENDBG_PRECEDENCE_HPP
