//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_BINARYOPERATOR_HPP
#define XENDBG_BINARYOPERATOR_HPP

#include <variant>

namespace xd::parser::op {

  class Add {};
  class Equals {};
  class Divide {};
  class Multiply {};
  class Subtract {};


  using BinaryOperator = std::variant<Add, Equals, Divide, Multiply, Subtract>;

}

#endif //XENDBG_BINARYOPERATOR_HPP
