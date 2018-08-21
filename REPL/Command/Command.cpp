//
// Created by Spencer Michaels on 8/19/18.
//

#include <iostream>

#include "Command.hpp"
#include "../../Util/string.hpp"

using xd::util::string::expect;
using xd::util::string::skip_whitespace;
using xd::repl::cmd::Action;
using xd::repl::cmd::Command;

#include <iostream>

std::optional<Action> Command::match(const std::string& s) const {
  const auto begin = s.begin();
  const auto end = s.end();

  auto next = expect(get_name(), skip_whitespace(begin, end), end);

  if (next == begin)
    return std::nullopt;

  for (const auto& verb : _verbs) {
    auto action = verb.match(next, end);
    if (action)
      return action;
  }

  return std::nullopt;
}

std::vector<std::string> Command::complete(const std::string& s) const {
  const auto begin = s.begin();
  const auto end = s.end();

  auto next = expect(get_name(), skip_whitespace(begin, end), end);

  // If s doesn't have this command as a prefix, neither this command
  // nor its children have any relevant completion options to give
  if (next == begin)
    return {};

  // If a verb has more specific completion options, return those instead
  for (const auto& verb : _verbs) {
    auto options = verb.complete(next, end);
    if (!options.empty())
      return options;
  }

  // Otherwise return the list of verbs
  std::vector<std::string> options;
  std::transform(_verbs.begin(), _verbs.end(), std::back_inserter(options),
    [](auto& verb) {
      return verb.get_name();
    });

  return options;
}
