//
// Created by Spencer Michaels on 8/19/18.
//

#include "Verb.hpp"
#include "../../Util/string.hpp"

#include <iostream>

using xd::util::string::expect;
using xd::util::string::skip_whitespace;

using xd::repl::cmd::Action;
using xd::repl::cmd::Verb;

std::optional<Action> Verb::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  auto new_begin = expect(_name, skip_whitespace(begin, end), end);

  if (new_begin == begin)
    return std::nullopt;

  return [](){}; // TODO!
}
