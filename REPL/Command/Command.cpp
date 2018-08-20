//
// Created by Spencer Michaels on 8/19/18.
//

#include "Command.hpp"
#include "../../Util/string.hpp"

using xd::util::string::expect;
using xd::util::string::skip_whitespace;
using xd::repl::cmd::Action;
using xd::repl::cmd::Command;

#include <iostream>

std::optional<Action> Command::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  auto new_begin = expect(_name, skip_whitespace(begin, end), end);

  if (new_begin == begin)
    return std::nullopt;

  for (const auto& verb : _verbs) {
    auto action = verb.match(new_begin, end);
    if (action)
      return action;
  }

  return std::nullopt;
}
