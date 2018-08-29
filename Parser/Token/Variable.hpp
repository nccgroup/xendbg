//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_TOKEN_VARIABLE_HPP
#define XENDBG_TOKEN_VARIABLE_HPP

#include <optional>
#include <regex>
#include <string>
#include <utility>

#include "TokenMatchResult.hpp"

namespace xd::parser::token {

  class Variable {
  public:
    explicit Variable(std::string name)
        : _name(std::move(name)) {}

    std::string name() const { return _name; };

  private:
    std::string _name;

  public:
    static TokenMatchResult<Variable> match(std::string::const_iterator begin, std::string::const_iterator end) {
      std::regex r("^\\$[A-Za-z][A-Za-z0-9_]*");
      std::smatch m;

      if (!std::regex_search(begin, end, m, r))
        return std::make_pair(std::nullopt, begin);

      auto new_begin = begin + m.position() + m.length();
      auto name = m.str().substr(1);

      return std::make_pair(Variable(name), new_begin);
    }
  };
}

#endif //XENDBG_VARIABLE_HPP
