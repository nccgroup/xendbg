//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_TOKEN_VARIABLE_HPP
#define XENDBG_TOKEN_VARIABLE_HPP

#include <string>

namespace xd::parser::token {

  class Variable {
  public:
    explicit Variable(std::string name)
        : _name(std::move(name)) {}

    std::string name() const { return _name; };

  private:
    std::string _name;
  };
}

#endif //XENDBG_VARIABLE_HPP
