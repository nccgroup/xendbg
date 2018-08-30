//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_BINARYOPERATOR_HPP
#define XENDBG_BINARYOPERATOR_HPP

#include <variant>

#include "Operator.hpp"

namespace xd::parser::expr::op {

  namespace {
    using BinOp = Operator<Arity::Binary>;
  }

  struct Add : public BinOp {};
  struct Equals : public BinOp {};
  struct Divide : public BinOp {};
  struct Multiply : public BinOp {};
  struct Subtract : public BinOp {};


  using BinaryOperator = std::variant<Add, Equals, Divide, Multiply, Subtract>;

}

#endif //XENDBG_BINARYOPERATOR_HPP
