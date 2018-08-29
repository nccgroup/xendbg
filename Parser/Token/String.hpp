//
// Created by Spencer Michaels on 8/28/18.
//

#ifndef XENDBG_TOKEN_STRING_HPP
#define XENDBG_TOKEN_STRING_HPP

#include <optional>
#include <regex>
#include <string>
#include <utility>

#include "TokenMatchResult.hpp"
#include "../../Util/string.hpp"

namespace xd::parser::token {

  class String {
  public:
    using Value = std::string;

  public:
    explicit String(Value value)
        : _value(std::move(value)) {}

    const Value& value() const { return _value; };

  private:
    Value _value;

  public:
    static TokenMatchResult<String> match(std::string::const_iterator begin, std::string::const_iterator end) {
      const auto new_end = util::string::match_optionally_quoted_string(begin, end);
      const auto value = std::string(begin, new_end);
      return std::make_pair(String(value), new_end);
    };
  };

}

#endif //XENDBG_TOKEN_STRING_HPP
