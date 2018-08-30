//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_BINARYOPERATOR_HPP
#define XENDBG_BINARYOPERATOR_HPP

#include <variant>

namespace xd::parser::expr::op {

  struct BinaryOperatorBase {};

  struct Add : public BinaryOperatorBase {};
  struct Equals : public BinaryOperatorBase {};
  struct Divide : public BinaryOperatorBase {};
  struct Multiply : public BinaryOperatorBase {};
  struct Subtract : public BinaryOperatorBase {};


  using BinaryOperator = std::variant<Add, Equals, Divide, Multiply, Subtract>;

}

#endif //XENDBG_BINARYOPERATOR_HPP
