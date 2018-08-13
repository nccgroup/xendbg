//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_BINARYOPERATOR_HPP
#define XENDBG_BINARYOPERATOR_HPP

namespace xd::parser::op {

  class BinaryOperator {};

  class Equals: public BinaryOperator {};
  class Add : public BinaryOperator {};
  class Subtract : public BinaryOperator {};
  class Multiply : public BinaryOperator {};
  class Divide: public BinaryOperator {};

}

#endif //XENDBG_BINARYOPERATOR_HPP
