//
// Created by Spencer Michaels on 8/19/18.
//

#include <iostream>

#include "Command.hpp"
#include "../../Util/IndentHelper.hpp"
#include "../../Util/string.hpp"

using xd::util::IndentHelper;
using xd::util::string::expect;
using xd::util::string::skip_whitespace;
using xd::repl::cmd::Action;
using xd::repl::cmd::Command;

void Command::print(std::ostream& out, IndentHelper& indent) const {
  out << indent
    << get_name()
    << ": "
    << get_description()
    << std::endl;

  indent.indent();
  for (const auto& verb : _verbs) {
    verb.print(out, indent);
  }
  indent.unindent();
}

std::optional<Action> Command::match(std::string::const_iterator begin, std::string::const_iterator end) const {
  const auto name_end = expect(get_name(), begin, end);

  if (name_end == begin)
    return std::nullopt;

  for (const auto& verb : _verbs) {
    auto action = verb.match(name_end, end);
    if (action)
      return action;
  }

  return std::nullopt;
}

std::optional<std::vector<std::string>> Command::complete(std::string::const_iterator begin, std::string::const_iterator end) const {
  const auto name_end = expect(get_name(), begin, end);

  // If s doesn't have this command as a prefix, neither this command
  // nor its children have any relevant completion options to give
  if (name_end == begin)
    return std::nullopt;

  // If a verb has more specific completion options, return those instead
  for (const auto& verb : _verbs) {
    auto options = verb.complete(name_end, end);

    if (options)
      return options;
  }

  // Otherwise return the list of verbs
  std::vector<std::string> options;
  options.reserve(_verbs.size());
  std::transform(_verbs.begin(), _verbs.end(), std::back_inserter(options),
    [](auto& verb) {
      return verb.get_name();
    });

  return options;
}
