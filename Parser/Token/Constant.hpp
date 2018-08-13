//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_TOKEN_CONSTANT_HPP
#define XENDBG_TOKEN_CONSTANT_HPP

namespace xd::parser::token {

  class Constant {
  public:
    using Value = int;

  public:
    explicit Constant(Value value)
        : _value(value) {}

    Value value() const { return _value; };

  private:
    Value _value;
  };

}

#endif //XENDBG_CONSTANT_HPP
