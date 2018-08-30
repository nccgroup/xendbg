//
// Created by Spencer Michaels on 8/11/18.
//

#ifndef XENDBG_TOKEN_CONSTANT_HPP
#define XENDBG_TOKEN_CONSTANT_HPP

#include <optional>
#include <regex>
#include <string>
#include <utility>

#include "TokenMatchResult.hpp"

namespace xd::parser::token {

  class Constant {
  public:
    using Value = uint64_t;

  public:
    explicit Constant(Value value)
        : _value(value) {}

    Value value() const { return _value; };

  private:
    Value _value;

  public:
    static TokenMatchResult<Constant> match(std::string::const_iterator begin, std::string::const_iterator end) {
      std::regex r("^([0-9]+)|(0x[0-9a-fA-F]+)|(0b[0-1]+)");
      std::smatch m;

      if (!std::regex_search(begin, end, m, r))
        return std::make_pair(std::nullopt, begin);

      auto value = std::stoi(m.str(), 0, 0);
      auto new_begin = begin + m.position() + m.length();

      return std::make_pair(Constant(value), new_begin);
    };
  };

}

#endif //XENDBG_CONSTANT_HPP
