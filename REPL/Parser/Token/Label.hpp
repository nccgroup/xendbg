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
      std::regex r("^\\&[A-Za-z_][A-Za-z0-9_]*");
      std::smatch m;

      if (!std::regex_search(begin, end, m, r))
        return std::make_pair(std::nullopt, begin);

      const auto label_end = begin + m.position() + m.length();
      const auto label_name = std::string(begin+1, label_end);

      return std::make_pair(Label(label_name), label_end);
    }
  };
}

#endif //XENDBG_TOKEN_LABEL_HPP
