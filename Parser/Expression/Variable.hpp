//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_EXPRESSION_VARIABLE_HPP
#define XENDBG_EXPRESSION_VARIABLE_HPP

#include <string>

#include "Expression.hpp"

namespace xd::parser::expr {

  class Variable : public Expression {
  public:
    explicit Variable(std::string n)
        : _name(std::move(n)) {};

    const std::string& name() const { return _name; };

  private:
    std::string _name;
  };

}

#endif //XENDBG_VARIABLE_HPP
