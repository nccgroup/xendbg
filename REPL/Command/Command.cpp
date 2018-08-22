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

std::optional<Action> Command::match(const std::string& s) const {
  auto verb_start = match_prefix_skipping_whitespace(s.begin(), s.end());

  if (verb_start == begin)
    return std::nullopt;

  for (const auto& verb : _verbs) {
    auto action = verb.match(verb_start, end);
    if (action)
      return action;
  }

  return std::nullopt;
}

std::optional<std::vector<std::string>> Command::complete(const std::string& s) const {
  auto verb_start = match_prefix_skipping_whitespace(s.begin(), s.end());

  // If s doesn't have this command as a prefix, neither this command
  // nor its children have any relevant completion options to give
  if (verb_start == s.begin())
    return std::nullopt;

  // If a verb has more specific completion options, return those instead
  for (const auto& verb : _verbs) {
    auto options = verb.complete(verb_start, end);
    if (options)
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

std::string::const_iterator Command::match_prefix_skipping_whitespace(
        std::string::const_iterator begin, std::string::const_iterator end) 
{
  const auto first_non_ws = skip_whitespace(begin, end);
  const auto start = expect(get_name(), first_non_ws, end);

  if (start == first_non_ws)
    return begin;

  return start;
}
