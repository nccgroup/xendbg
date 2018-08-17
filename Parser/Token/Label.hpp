//
// Created by Spencer Michaels on 8/12/18.
//

#ifndef XENDBG_TOKEN_LABEL_HPP
#define XENDBG_TOKEN_LABEL_HPP

#include <optional>
#include <regex>
#include <string>
#include <utility>

#include "TokenMatchResult.hpp"

namespace xd::parser::token {

  class Label {
  public:
    explicit Label(std::string name)
        : _name(std::move(name)) {}

    std::string name() const { return _name; };

  private:
    std::string _name;

  public:
    static TokenMatchResult<Label> match(std::string::const_iterator begin, std::string::const_iterator end) {
      std::regex r("^\\&[A-Za-z][A-Za-z0-9_]*");
      std::smatch m;

      if (!std::regex_search(begin, end, m, r))
        return std::make_pair(std::optional<Label>(), begin);

      auto new_begin = begin + m.position() + m.length();

      return std::make_pair(Label(m.str()), new_begin);
    }
  };
}

#endif //XENDBG_TOKEN_LABEL_HPP
