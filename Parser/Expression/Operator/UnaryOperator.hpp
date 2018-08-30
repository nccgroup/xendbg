//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_UNARYOPERATOR_HPP
#define XENDBG_UNARYOPERATOR_HPP

#include <variant>

namespace xd::parser::op {

  struct Dereference {};
  struct Negate {};

  using UnaryOperator = std::variant<Dereference, Negate>;

}

#endif //XENDBG_UNARYOPERATOR_HPP
