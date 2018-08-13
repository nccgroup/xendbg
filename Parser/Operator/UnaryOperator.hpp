//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_UNARYOPERATOR_HPP
#define XENDBG_UNARYOPERATOR_HPP

namespace xd::parser::op {

  class UnaryOperator {};

  class Negate : public UnaryOperator {};
  class Dereference : public UnaryOperator {};

}

#endif //XENDBG_UNARYOPERATOR_HPP
